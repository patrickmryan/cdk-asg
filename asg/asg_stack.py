import sys
from aws_cdk import (
    Duration,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_autoscaling as autoscaling,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2targets,
)
from constructs import Construct
import boto3


class AsgStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

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
cat > /var/www/html/index.htm<<__EOF__
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
            machine_image=ec2.MachineImage.latest_amazon_linux(),  #'ami-09d3b3274b6c5d4aa'
            role=instance_role,
            security_group=unrestricted_sg,
            user_data=user_data,
        )

        # vpc_subnets
        tag_key = "CWALL_ROLE"
        tag_value = "ECHO"

        ec2_resource = boto3.resource("ec2")
        vpc_resource = ec2_resource.Vpc(vpc_id)
        all_subnets = vpc_resource.subnets.all()
        subnet_ids = []
        for subnet in all_subnets:
            tags = {tag["Key"]: tag["Value"] for tag in subnet.tags}  # dict-ify
            if tags[tag_key] == tag_value:
                subnet_ids.append(subnet.subnet_id)

        vpc_subnets = ec2.SubnetSelection(
            subnets=[
                ec2.Subnet.from_subnet_id(self, "Subnet-" + subnet_id, subnet_id)
                for subnet_id in subnet_ids
            ]
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
            min_capacity=0,
            # notifications
            vpc_subnets=vpc_subnets,
        )

        # ALB
        # target group
        # scaling topic(s)
        # event rules
        # lambdas attached to rules(super basic)
