import os
import aws_cdk as cdk
from asg.asg_stack import AsgStack
from cdk_nag import AwsSolutionsChecks

env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION")
)

app = cdk.App()
AsgStack(app, "AsgStack", env=env)
# cdk.Aspects.of(app).add(AwsSolutionsChecks())

app.synth()
