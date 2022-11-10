import json
import sys
from datetime import datetime, timezone
from os.path import join

import boto3
from aws_cdk import (
    Duration,
    Stack,
    aws_autoscaling as autoscaling,
    aws_autoscaling_hooktargets as hooktargets,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2targets,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    custom_resources as cr,
)
from constructs import Construct


class AsgStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        permissions_boundary_policy_arn = self.node.try_get_context(
            "PermissionsBoundaryPolicyArn"
        )
        if not permissions_boundary_policy_arn:
            permissions_boundary_policy_name = self.node.try_get_context(
                "PermissionsBoundaryPolicyName"
            )
            if permissions_boundary_policy_name:
                permissions_boundary_policy_arn = self.format_arn(
                    service="iam",
                    region="",
                    account=self.account,
                    resource="policy",
                    resource_name=permissions_boundary_policy_name,
                )

        if permissions_boundary_policy_arn:
            policy = iam.ManagedPolicy.from_managed_policy_arn(
                self, "PermissionsBoundary", permissions_boundary_policy_arn
            )
            iam.PermissionsBoundary.of(self).apply(policy)

        subnet_tagging = self.node.try_get_context("SubnetTagging")
        desired_capacity = self.node.try_get_context("DesiredCapacity")
        if not desired_capacity:
            desired_capacity = 0

        self.ec2_resource = boto3.resource("ec2")

        # get the VPC

        vpc_id = self.node.try_get_context("VpcId")
        vpc = ec2.Vpc.from_lookup(self, "Vpc", vpc_id=vpc_id)

        # vpc_name = self.node.try_get_context("VpcName")
        # vpc = ec2.Vpc.from_lookup(self, "Vpc", tags={"Name": vpc_name })

        # if not vpc:
        #     print(f"could not find VPC named {vpc_name}")
        #     sys.exit(1)

        # vpc_id = vpc.vpc_id
        # print(vpc_id)

        key_name = self.node.try_get_context("KeyName")

        # security group(s)
        unrestricted_sg = ec2.SecurityGroup(self, "Unrestricted", vpc=vpc)
        # internal_range = ec2.Peer.ipv4(vpc.vpc_cidr_block)
        unrestricted_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))
        unrestricted_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))

        # role(s)
        instance_role = iam.Role(
            self,
            "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess")
            ],
        )

        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            """
yum update -y
yum install httpd -y
name=$(curl http://169.254.169.254/latest/meta-data/local-hostname)
cat > /var/www/html/index.html <<__EOF__
<title>$name</title>
<h1>welcome to $name</h1>
__EOF__

systemctl enable httpd
systemctl start httpd
"""
        )

        # launch template
        template = ec2.LaunchTemplate(
            self,
            "LaunchTemplate",
            # block_devices
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3, ec2.InstanceSize.MICRO
            ),
            key_name=key_name,
            machine_image=ec2.AmazonLinuxImage(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            role=instance_role,
            security_group=unrestricted_sg,
            user_data=user_data,
        )

        # vpc_subnets
        vpc_resource = self.ec2_resource.Vpc(vpc_id)

        subnets = self.get_subnets_tagged(
            vpc=vpc_resource,
            tag_key=subnet_tagging["DataSubnetKey"],
            tag_value=subnet_tagging["DataSubnetValue"],
            prefix="Data",
        )
        if not subnets:
            print("tag_key=" + subnet_tagging["DataSubnetKey"])
            print("tag_value=" + subnet_tagging["DataSubnetValue"])
            print("no subnets with sufficient address space")
            sys.exit(1)

        asg_name = "asg-" + self.stack_name
        asg_arn = f"arn:{self.partition}:autoscaling:{self.region}:{self.account}:autoScalingGroup:*:autoScalingGroupName/{asg_name}"

        # ASG
        asg = autoscaling.AutoScalingGroup(
            self,
            "ASG",
            vpc=vpc,
            auto_scaling_group_name=asg_name,
            launch_template=template,
            # associate_public_ip_address
            # group_metrics
            # health_check
            # instance_monitoring
            desired_capacity=0,  # use desired_capacity later!
            min_capacity=0,
            max_capacity=4,
            # notifications
            # termination_policies
            # update_policy
            vpc_subnets=ec2.SubnetSelection(subnets=subnets),
        )

        # ALB
        subnets = self.get_subnets_tagged(
            vpc=vpc_resource,
            tag_key=subnet_tagging["ManagementSubnetKey"],
            tag_value=subnet_tagging["ManagementSubnetValue"],
            prefix="Management",
        )
        if not subnets:
            print("no subnets with sufficient address space")
            sys.exit(1)

        alb = elbv2.ApplicationLoadBalancer(
            self,
            "ALB",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=subnets),
            internet_facing=False,
        )
        listener = alb.add_listener(
            "Listener",
            port=80,
            open=True,
        )
        listener.add_targets("WebServers", port=80, targets=[asg])

        # setting for all python Lambda functions
        lambda_root = "lambdas"
        runtime = _lambda.Runtime.PYTHON_3_9
        log_retention = logs.RetentionDays.ONE_WEEK
        lambda_principal = iam.ServicePrincipal("lambda.amazonaws.com")
        basic_lambda_policy = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaBasicExecutionRole"
        )
        managed_policies = [basic_lambda_policy]
        lambda_role = iam.Role(
            self,
            "LaunchingHookRole",
            assumed_by=lambda_principal,
            managed_policies=managed_policies,
            inline_policies={
                "CompleteLaunch": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["autoscaling:CompleteLifecycleAction"],
                            resources=[asg_arn],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:Describe*"],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:CreateTags"],
                            resources=[
                                f"arn:{self.partition}:ec2:{self.region}:{self.account}:instance/*"
                            ],
                        ),
                    ],
                )
            },
        )

        launching_hook_lambda = _lambda.Function(
            self,
            "LaunchingHookLambda",
            runtime=runtime,
            code=_lambda.Code.from_asset(join(lambda_root, "launching_hook")),
            handler="launching_hook.lambda_handler",
            timeout=Duration.seconds(60),
            role=lambda_role,
            log_retention=log_retention,
        )

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.custom_resources/AwsCustomResource.html

        set_launch_hook_sdk_call = cr.AwsSdkCall(
            service="AutoScaling",
            action="putLifecycleHook",
            parameters={
                "AutoScalingGroupName": asg_name,
                "LifecycleHookName": "InstanceLaunchingHook",
                "DefaultResult": "ABANDON",
                "HeartbeatTimeout": 120,
                "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
                "NotificationMetadata": json.dumps(
                    {"message": "here is some cool metadata"}
                ),
            },
            physical_resource_id=cr.PhysicalResourceId.of(
                "PutLaunchHookSetting" + datetime.now(timezone.utc).isoformat()
            ),
        )

        launch_hook_resource = cr.AwsCustomResource(
            self,
            "LaunchHookResource",
            on_create=set_launch_hook_sdk_call,
            on_update=set_launch_hook_sdk_call,  # update just does the same thing as create.
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "autoscaling:PutLifecycleHook",
                            "autoscaling:DeleteLifecycleHook",
                        ],
                        resources=[asg_arn],
                    )
                ]
            ),
        )
        # the launch hook resource should not execute until AFTER the ASG been deployed
        launch_hook_resource.node.add_dependency(asg)

        set_desired_instances_sdk_call = cr.AwsSdkCall(
            service="AutoScaling",
            action="updateAutoScalingGroup",
            parameters={
                "AutoScalingGroupName": asg_name,
                "DesiredCapacity": desired_capacity,
            },
            physical_resource_id=cr.PhysicalResourceId.of(
                "PutDesiredInstancesSetting" + datetime.now(timezone.utc).isoformat()
            ),
        )

        asg_update_resource = cr.AwsCustomResource(
            self,
            "DesiredInstancesResource",
            on_create=set_desired_instances_sdk_call,
            on_update=set_desired_instances_sdk_call,  # update just does the same thing as create.
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=["autoscaling:updateAutoScalingGroup"],
                        resources=[asg_arn],
                    )
                ]
            ),
        )

        launching_rule = events.Rule(
            self,
            "LaunchingHookRule",
            event_pattern=events.EventPattern(
                source=["aws.autoscaling"],
                detail={
                    "LifecycleTransition": ["autoscaling:EC2_INSTANCE_LAUNCHING"],
                    "AutoScalingGroupName": [asg_name],
                },
            ),
            targets=[events_targets.LambdaFunction(launching_hook_lambda)],
        )

        # Make sure the launching rule and lambda are created before the ASG.
        # Bad things can happen if the ASG starts spinning up instances before the
        # lambdas and rules are deployed.
        asg.node.add_dependency(launching_rule)

        # set desired_instances AFTER the ASG, hook, lambda, and rule are all deployed.
        asg_update_resource.node.add_dependency(asg)
        asg_update_resource.node.add_dependency(launching_rule)

    def get_subnets_tagged(self, vpc=None, tag_key=None, tag_value=None, prefix=""):

        subnets = []
        for subnet in vpc.subnets.all():
            tags = {tag["Key"]: tag["Value"] for tag in subnet.tags}  # dict-ify

            if subnet.available_ip_address_count < 8:
                continue

            if tags[tag_key] != tag_value:
                continue

            subnets.append(
                ec2.Subnet.from_subnet_id(
                    self,
                    prefix + subnet.subnet_id,
                    subnet.subnet_id,
                )
            )

        return subnets
