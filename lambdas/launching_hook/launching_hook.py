import os
import json
import logging
import re
import boto3
import botocore
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def update_name_tag(ec2_client=None, instance_id="", name_tag=""):

    response = ec2_client.create_tags(
        Resources=[instance_id], Tags=[{"Key": "Name", "Value": name_tag}]
    )
    return response


def lambda_handler(event, context):

    logger.info(json.dumps(event))

    ec2_client = boto3.client("ec2")
    autoscaling = boto3.client("autoscaling")

    instance_id = event["instance_id"]

    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    inst_details = response["Reservations"][0]["Instances"][0]
    az = inst_details["Placement"]["AvailabilityZone"]

    new_name = "web_" + re.sub(r"\.", "_", inst_details["PrivateIpAddress"]) + f"_{az}"
    update_name_tag(ec2_client=ec2_client, instance_id=instance_id, name_tag=new_name)

    params = event.copy()
    print(f"calling autoscaling.complete_lifecycle_action({params})")
    try:
        response = autoscaling.complete_lifecycle_action(**params)
    except ClientError as e:
        message = "Error completing lifecycle action: {}".format(e)
        print(message)

    print(response)

    # event_detail = event["detail"]
    # # NotificationMetedata stores the name of the SSM param that contains the CI metadata
    # ci_configuration_param = event_detail["NotificationMetadata"]

    # key = "PAVM_LAUNCH_STATE_MACHINE_ARN"
    # state_machine_arn = os.environ.get(key, None)
    # if not state_machine_arn:
    #     raise Exception(f"could not find value for state machine ARN {key} in ENV")

    # # go get the SSM parameter values
    # ssm_client = boto3.client("ssm")

    # resp = ssm_client.get_parameter(Name=ci_configuration_param, WithDecryption=True)
    # ci_configuration = json.loads(resp["Parameter"]["Value"])

    # sfn_client = boto3.client("stepfunctions")

    # # need to introspect some info about the instance
    # result = None
    # ec2_client = boto3.client("ec2")
    # instance_id = event_detail["EC2InstanceId"]
    # try:
    #     result = ec2_client.describe_instances(InstanceIds=[instance_id])
    #     # there can only be one
    #     inst = result["Reservations"][0]["Instances"][0]
    #     vpc_id = inst["VpcId"]
    #     # ftd_ip = inst["PrivateIpAddress"]
    #     az = inst["Placement"]["AvailabilityZone"]

    # except ClientError as e:
    #     print(f"Error describing the instance {instance_id}: {e}")
    #     # .format( instance_id, e.response["Error"]
    #     raise e
    #     # pass

    # # payload to kick off step function
    # sf_input = {
    #     "launching_pavm": {
    #         "lifecycle_hook_details": event_detail,
    #         # "configuration_ssm_parameter" : ci_configuration,
    #         "ci_configuration": ci_configuration,
    #         "instance_id": instance_id,
    #         "availability_zone": az,
    #         "vpc_id": vpc_id,
    #     }
    # }

    # task_name = f"pavm-{az}-{instance_id}"

    # # kick off the step function to create a new PAVM
    # response = sfn_client.start_execution(
    #     stateMachineArn=state_machine_arn, name=task_name, input=json.dumps(sf_input)
    # )
    # print(response)
    # return {"executionArn": response["executionArn"]}
