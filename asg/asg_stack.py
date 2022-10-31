import sys
from os.path import join

from aws_cdk import (
    Duration,
    Stack,
    Resource,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_autoscaling as autoscaling,
    aws_autoscaling_hooktargets as hooktargets,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2targets,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_events as events,
    aws_events_targets as events_targets,
    custom_resources,
)
from constructs import Construct
import boto3


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

        self.ec2_resource = boto3.resource("ec2")

        # get the VPC
        vpc_id = self.node.try_get_context("VpcId")
        vpc = ec2.Vpc.from_lookup(self, "Vpc", vpc_id=vpc_id)

        key_name = self.node.try_get_context("KeyName")

        # security group(s)
        unrestricted_sg = ec2.SecurityGroup(self, "Unrestricted", vpc=vpc)
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
        )

        asg_name = "asg-" + self.stack_name

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
        )

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
            # 'open: true' is the default, you can leave it out if you want. Set it
            # to 'false' and use `listener.connections` if you want to be selective
            # about who can access the load balancer.
            open=True,
        )
        listener.add_targets("WebServers", port=80, targets=[asg])

        # scaling topic(s)

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
                            actions=["autoscaling:CompleteLifecycleAction"],
                            effect=iam.Effect.ALLOW,
                            resources=[asg.auto_scaling_group_arn],
                        ),
                        iam.PolicyStatement(
                            actions=["ec2:Describe*", "ec2:CreateTag*"],
                            effect=iam.Effect.ALLOW,
                            resources=[
                                f"arn:{self.partition}:ec2:*:{self.account}:instance/*"
                            ]
                            # maybe add a condition to restrict this to instances in the ASG
                        ),
                    ],
                )
            },
        )

        launching_hook_lambda = _lambda.Function(
            self,
            "LaunchingHook",
            runtime=runtime,
            code=_lambda.Code.from_asset(join(lambda_root, "launching_hook")),
            handler="launching_hook.lambda_handler",
            timeout=Duration.seconds(60),
            role=lambda_role,
            log_retention=log_retention,
        )

        # https://medium.com/cyberark-engineering/advanced-custom-resources-with-aws-cdk-1e024d4fb2fa
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk/CustomResource.html
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.custom_resources/Provider.html

        # asg.add_lifecycle_hook(
        #     id="LaunchingHook",
        #     lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,
        #     default_result=autoscaling.DefaultResult.ABANDON,
        #     heartbeat_timeout=Duration.minutes(2),
        #     lifecycle_hook_name="LaunchingHook",
        #     notification_target=hooktargets.FunctionHook(launching_hook_lambda),
        # )

        # launching_rule = events.Rule(
        #     self,
        #     "LaunchingHookRule",
        #     event_pattern=events.EventPattern(
        #         source=["aws.autoscaling"],
        #         detail={
        #             "LifecycleTransition": ["autoscaling:EC2_INSTANCE_LAUNCHING"],
        #             "AutoScalingGroupName": [asg_name],
        #         },
        #     ),
        #     targets=[events_targets.LambdaFunction(launching_hook_lambda)],
        # )

        # lifecycle_hook_props = autoscaling.LifecycleHookProps(
        #     auto_scaling_group=asg,
        #     lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,

        #     # the properties below are optional
        #     default_result=autoscaling.DefaultResult.ABANDON,
        #     heartbeat_timeout=Duration.minutes(3),
        #     lifecycle_hook_name="InstanceLaunchingHook",
        #     # notification_metadata="notificationMetadata",
        #     notification_target=hooktargets.FunctionHook(launching_hook_lambda),
        #     # role=role
        # )

        # lifecycle_hook = autoscaling.LifecycleHook(self, "InstanceLaunchingHook",
        #     auto_scaling_group=asg,
        #     lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,

        #     # the properties below are optional
        #     default_result=autoscaling.DefaultResult.ABANDON,
        #     # heartbeat_timeout=cdk.Duration.minutes(30),
        #     # lifecycle_hook_name="lifecycleHookName",
        #     # notification_metadata="notificationMetadata",
        #     notification_target=lifecycle_hook_target,
        #     # role=role
        # )

        # make sure the rules are deploed before the ASG
        # asg.node.add_dependency(launching_rule)

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_autoscaling/LifecycleHook.html

    def get_subnets_tagged(self, vpc=None, tag_key=None, tag_value=None):

        subnets = []
        for subnet in vpc.subnets.all():
            tags = {tag["Key"]: tag["Value"] for tag in subnet.tags}  # dict-ify
            if tags[tag_key] == tag_value:
                subnets.append(
                    ec2.Subnet.from_subnet_id(
                        self,
                        tag_key + subnet.subnet_id,
                        subnet.subnet_id,
                    )
                )

        return subnets
