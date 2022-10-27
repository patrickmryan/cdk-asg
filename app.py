import os
import aws_cdk as cdk
from asg.asg_stack import AsgStack

env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION")
)

app = cdk.App()
AsgStack(app, "AsgStack", env=env)

app.synth()
