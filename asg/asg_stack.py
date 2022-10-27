import sys
from os.path import join

from aws_cdk import (
    Duration,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_autoscaling as autoscaling,
    aws_autoscaling_hooktargets as hooktargets,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2targets,
    aws_lambda as _lambda,
    aws_logs as logs,
)
from constructs import Construct
import boto3


class AsgStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

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
            # block_devices)
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3, ec2.InstanceSize.MICRO
            ),
            key_name=key_name,
            machine_image=ec2.AmazonLinuxImage(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            # machine_image=ec2.MachineImage.lookup("amzn2-ami-kernel-*"),
            # filters={"image-id": "ami-09d3b3274b6c5d4aa"}
            role=instance_role,
            security_group=unrestricted_sg,
            user_data=user_data,
        )

        # vpc_subnets
        vpc_resource = self.ec2_resource.Vpc(vpc_id)

        subnets = self.get_subnets_tagged(
            vpc=vpc_resource, tag_key="CWALL_ROLE", tag_value="ECHO"
        )

        # ASG
        asg = autoscaling.AutoScalingGroup(
            self,
            "ASG",
            vpc=vpc,
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
            vpc=vpc_resource, tag_key="CWALL_ROLE", tag_value="EGRESS"
        )

        alb = elbv2.ApplicationLoadBalancer(
            self,
            "ALB",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=subnets),
            internet_facing=True,
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
                "complete": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            actions=["autoscaling:CompleteLifecycleAction"],
                            effect=iam.Effect.ALLOW,
                            resources=[asg.auto_scaling_group_arn],
                        )
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

        asg.add_lifecycle_hook(
            id="LaunchingHook",
            lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,
            default_result=autoscaling.DefaultResult.ABANDON,
            heartbeat_timeout=Duration.minutes(5),
            lifecycle_hook_name="LaunchingHook",
            notification_target=hooktargets.FunctionHook(launching_hook_lambda),
            # role=asg_topic_pub_role,
        )

        # lifecycle_hook = autoscaling.LifecycleHook(
        #     self,
        #     "Launching",
        #     auto_scaling_group=asg,
        #     lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,
        #     # the properties below are optional
        #     default_result=autoscaling.DefaultResult.CONTINUE,
        #     # heartbeat_timeout=cdk.Duration.minutes(30),
        #     # lifecycle_hook_name="lifecycleHookName",
        #     # notification_metadata="notificationMetadata",
        #     notification_target=launching_hook_lambda,
        #     # role=role
        # )

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_autoscaling/LifecycleHook.html

        # event rules
        # lambdas attached to rules(super basic)

    def get_subnets_tagged(self, vpc=None, tag_key=None, tag_value=None):

        subnets = []
        for subnet in vpc.subnets.all():
            tags = {tag["Key"]: tag["Value"] for tag in subnet.tags}  # dict-ify
            if tags[tag_key] == tag_value:
                subnets.append(
                    ec2.Subnet.from_subnet_id(
                        self, "Subnet-" + subnet.subnet_id, subnet.subnet_id
                    )
                )

        return subnets
