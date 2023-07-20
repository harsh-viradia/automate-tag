import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    # Initialize AWS resources and clients
    ec2 = boto3.resource('ec2')  # AWS EC2 resource
    elbv2 = boto3.client('elbv2')  # AWS Elastic Load Balancing V2 client
    lambda_client = boto3.client('lambda')  # AWS Lambda client
    cloudtrail = boto3.client('cloudtrail')  # AWS CloudTrail client
    s3 = boto3.client('s3')  # AWS S3 client
    rds = boto3.client('rds')  # AWS RDS client
    kms = boto3.client('kms') # AWS KMS client
    ecs = boto3.client('ecs') # AWS ECS client
    eks = boto3.client('eks') # AWS EKS client

    # For troubleshooting: Print the event object as a JSON string
    print(json.dumps(event))

    # Initialize lists to store resource IDs
    volume_ids = [] # List to store EBS Volume ids
    snapshot_ids = [] # List to store Snapshot ids
    image_ids = [] # List to store AMI image ids
    eni_ids = [] # List to store ENI ids
    ec2_ids = []  # List to store EC2 instance ids
    elb_arns = []  # List to store ALB arns
    lambda_function_arn = []  # List to store Lambda Function arn
    vpc_ids = []  # List to store VPC ids
    igw_ids = []  # List to store Internet Gateway ids
    natgw_ids = []  # List to store NAT Gateway ids
    eip_ids = []  # List to store Elastic IP ids
    trail_arns = [] # List to store CloudTrail trail names
    s3_buckets = [] # List to store S3 bucket names
    rds_db_arns = []  # List to store RDS DB arns
    rds_snapshot_arns = []  # List to store RDS DB Snapshot arns
    rds_db_instance_replica_arns = []  # List to store RDS DB Instance Read Replica identifiers
    rds_db_cluster_arns = []  # List to store RDS DB Cluster arns
    rds_db_cluster_snapshot_arns = []  # List to store RDS DB Cluster Snapshot arns
    kms_key_arns = [] # List to store KMS Key arns
    ecs_cluster_arns = [] # List to store ECS Cluster arns
    ecs_task_definition_arns = [] # List to store ECS task definition arns
    ecs_service_arns = [] # List to store ECS service arns
    eks_nodegroup_arns = [] # List to store EKS NodeGroup arns
    eks_cluster_arns = [] # List to store EKS Cluster arns


    # For troubleshooting: Print the 'detail' object from the event
    print(event['detail'])

    # Extract relevant information from the event
    region = event['region']
    detail = event['detail']
    eventName = detail['eventName']
    eventSource = detail['eventSource']
    user_type = detail['userIdentity']['type']
    arn = detail['userIdentity']['arn']
    principal = detail['userIdentity']['principalId']

    # Extracting email-id of the resource creator from the principal name
    if user_type == 'IAMUser':
        user = detail['userIdentity']['userName']
    else:
        user = principal.split(':')[1]

    # Get the current date
    current_date = datetime.now().strftime("%m-%d-%Y")

    # Print relevant information for troubleshooting
    print('Region Name: ' + region)
    print('Event Source: ' + eventSource)
    print('Event Name: ' + eventName)
    print('User Name: ' + user)

    # Check if 'responseElements' are present in the event for events other than S3 Bucket Creation.
    if not detail['responseElements']:
        # If it is a S3 bucket creation event tag S3.
        if eventName == 'CreateBucket':
            s3_buckets.append(detail['requestParameters']['bucketName'])
            print(s3_buckets)
            # Add tags to S3 Buckets
            if s3_buckets:
                for bucket in s3_buckets:
                    s3.put_bucket_tagging(Bucket=bucket, Tagging={
                    'TagSet': [
                        {'Key': 'AutoOwner', 'Value': user},
                        {'Key': 'AutoDate', 'Value': current_date},
                    ]
                })
            return True
        
        # In case response elements are unavailable
        print("ResponseElement is missing. There could be an error that occurred.")
        if detail['errorCode']:
            print('Error Code: ' + detail['errorCode'])
        if detail['errorMessage']:
            print('Error Message: ' + detail['errorMessage'])
        return False
    else:
        # Process the event based on the 'eventName'. Identify the API call and append to relevant list.
        if eventName == 'CreateVolume':
            volume_ids.append(detail['responseElements']['volumeId'])
            print(volume_ids)
        elif eventName == 'CreateSnapshot':
            snapshot_ids.append(detail['responseElements']['snapshotId'])
            print(snapshot_ids)
        elif eventName == 'CreateImage':
            image_ids.append(detail['responseElements']['imageId'])
            print(image_ids)
        elif eventName == 'CreateNetworkInterface':
            eni_ids.append(detail['responseElements']['networkInterface']['networkInterfaceId'])
            print(eni_ids)
        elif eventName == 'RunInstances':
            default_items = detail['responseElements']['instancesSet']['items']
            for item in default_items:
                ec2_ids.append(item['instanceId'])
                print(ec2_ids)
                 # To extract ids of default created resources with EC2
                base = ec2.instances.filter(InstanceIds=ec2_ids)
                for inst in base:
                    for vol in inst.volumes.all():
                        volume_ids.append(vol.id)
                        print(volume_ids)
                    for eni in inst.network_interfaces:
                        eni_ids.append(eni.id)
                        print(eni_ids)
        elif eventName == 'CreateLoadBalancer':
            elb_arns.append(detail['responseElements']['loadBalancers'][0]['loadBalancerArn'])
            print(elb_arns)
        elif eventName == 'CreateFunction20150331':
            lambda_function_arn.append(detail['responseElements']['functionArn'])
            print(lambda_function_arn)
        elif eventName == 'CreateVpc':
            vpc_ids.append(detail['responseElements']['vpc']['vpcId'])
            print(vpc_ids)
        elif eventName == 'CreateInternetGateway':
            igw_ids.append(detail['responseElements']['internetGateway']['internetGatewayId'])
            print(igw_ids)
        elif eventName == 'CreateNatGateway':
            natgw_ids.append(detail['responseElements']['CreateNatGatewayResponse']['natGateway']['natGatewayId'])
            print(natgw_ids)
        elif eventName == 'AllocateAddress':
            eip_ids.append(detail['responseElements']['allocationId'])
            print(eip_ids)
        elif eventName == 'CreateTrail':
            trail_arns.append(detail['responseElements']['trailARN'])
            print(trail_arns)
        elif eventName == 'CreateDBInstance':
            rds_db_arns.append(detail['responseElements']['dBInstanceArn'])
            print(rds_db_arns)
        elif eventName == 'CreateDBSnapshot':
            rds_snapshot_arns.append(detail['responseElements']['dBSnapshotArn'])
            print(rds_snapshot_arns)
        elif eventName == 'CreateDBInstanceReadReplica':
            rds_db_instance_replica_arns.append(detail['responseElements']['dBInstanceArn'])
            print(rds_db_instance_replica_arns)
        elif eventName == 'CreateDBCluster':
            rds_db_cluster_arns.append(detail['responseElements']['dBClusterArn'])
            print(rds_db_cluster_arns)
        elif eventName == 'CreateDBClusterSnapshot':
            rds_db_cluster_snapshot_arns.append(detail['responseElements']['dBClusterSnapshotArn'])
            print(rds_db_cluster_snapshot_arns)
        elif eventName == 'CreateKey':
            kms_key_arns.append(detail['responseElements']['keyMetadata']['arn'])
            print(kms_key_arns)
        elif eventName == 'CreateCluster' and eventSource == 'ecs.amazonaws.com':
            ecs_cluster_arns.append(detail['responseElements']['cluster']['clusterArn'])
            print(ecs_cluster_arns)
        elif eventName == 'RegisterTaskDefinition':
            ecs_task_definition_arns.append(detail['responseElements']['taskDefinition']['taskDefinitionArn'])
            print(ecs_task_definition_arns)
        elif eventName == 'CreateService':
            ecs_service_arns.append(detail['responseElements']['service']['serviceArn'])
            print(ecs_service_arns)
        elif eventName == 'CreateNodegroup':
            eks_nodegroup_arns.append(detail['responseElements']['nodegroup']['nodegroupArn'])
            print(eks_nodegroup_arns)
        elif eventName == 'CreateCluster' and eventSource == 'eks.amazonaws.com':
            eks_cluster_arns.append(detail['responseElements']['cluster']['arn'])
            print(eks_cluster_arns)


        # Add tags to EBS Volumes
        if volume_ids:
            ec2.create_tags(Resources=volume_ids, Tags=[
            {'Key': 'AutoOwner', 'Value': user},
            {'Key': 'AutoDate', 'Value': current_date},
        ])
            
         # Add tags to EBS Snapshots
        if snapshot_ids:
            ec2.create_tags(Resources=snapshot_ids, Tags=[
            {'Key': 'AutoOwner', 'Value': user},
            {'Key': 'AutoDate', 'Value': current_date},
        ])
            
         # Add tags to ENIs
        if eni_ids:
            ec2.create_tags(Resources=eni_ids, Tags=[
            {'Key': 'AutoOwner', 'Value': user},
            {'Key': 'AutoDate', 'Value': current_date},
        ])
            
        # Add tags to AMI image
        if image_ids:
            ec2.create_tags(Resources=image_ids, Tags=[
            {'Key': 'AutoOwner', 'Value': user},
            {'Key': 'AutoDate', 'Value': current_date},
        ])

        # Add tags to EC2 instances
        if ec2_ids:
            ec2.create_tags(Resources=ec2_ids, Tags=[
            {'Key': 'AutoOwner', 'Value': user},
            {'Key': 'AutoDate', 'Value': current_date},
        ])

        # Add tags to ELBs
        if elb_arns:
            for elb in elb_arns:
                elbv2.add_tags(ResourceArns=elb, Tags=[
                {'Key': 'AutoOwner', 'Value': user},
                {'Key': 'AutoDate', 'Value': current_date},
            ])

        # Add tags to Lambda functions
        if lambda_function_arn:
            for arn in lambda_function_arn:
                lambda_client.tag_resource(Resource=arn, Tags={
                    'AutoOwner': user,
                    'AutoDate': current_date
                })

         # Add tags to VPCs
        if vpc_ids:
            for vpc in vpc_ids:
                ec2.create_tags(Resources=vpc, Tags=[
                {'Key': 'AutoOwner', 'Value': user},
                {'Key': 'AutoDate', 'Value': current_date},
            ])

        # Add tags to Internet Gateways
        if igw_ids:
            for igw in igw_ids:
                ec2.create_tags(Resources=igw, Tags=[
                {'Key': 'AutoOwner', 'Value': user},
                {'Key': 'AutoDate', 'Value': current_date},
            ])

        # Add tags to NAT Gateways
        if natgw_ids:
            for natgw in natgw_ids:
                ec2.create_tags(Resources=natgw, Tags=[
                {'Key': 'AutoOwner', 'Value': user},
                {'Key': 'AutoDate', 'Value': current_date},
            ])

        # Add tags to Elastic IPs
        if eip_ids:
            for eip in eip_ids:
                ec2.create_tags(Resources=eip, Tags=[
                {'Key': 'AutoOwner', 'Value': user},
                {'Key': 'AutoDate', 'Value': current_date},
            ])

        # Add tags to CloudTrail Trails
        if trail_arns:
            for trail in trail_arns:
                cloudtrail.add_tags(ResourceId=trail, TagsList=[
                {'Key': 'AutoOwner', 'Value': user},
                {'Key': 'AutoDate', 'Value': current_date},
            ])

        # Add tags to RDS DB instances
        if rds_db_arns:
            for db_arn in rds_db_arns:
                rds.add_tags_to_resource(ResourceName=db_arn, Tags=[
                    {'Key': 'AutoOwner', 'Value': user},
                    {'Key': 'AutoDate', 'Value': current_date},
                ])

        # Add tags to RDS DB snapshots
        if rds_snapshot_arns:
            for snapshot_arn in rds_snapshot_arns:
                rds.add_tags_to_resource(ResourceName=snapshot_arn, Tags=[
                    {'Key': 'AutoOwner', 'Value': user},
                    {'Key': 'AutoDate', 'Value': current_date},
                ])

        # Add tags to RDS DB instance read replicas
        if rds_db_instance_replica_arns:
            for replica_arn in rds_db_instance_replica_arns:
                rds.add_tags_to_resource(ResourceName=replica_arn, Tags=[
                    {'Key': 'AutoOwner', 'Value': user},
                    {'Key': 'AutoDate', 'Value': current_date},
                ])

        # Add tags to RDS DB clusters
        if rds_db_cluster_arns:
            for cluster_arn in rds_db_cluster_arns:
                rds.add_tags_to_resource(ResourceName=cluster_arn, Tags=[
                    {'Key': 'AutoOwner', 'Value': user},
                    {'Key': 'AutoDate', 'Value': current_date},
                ])

        # Add tags to RDS DB cluster snapshots
        if rds_db_cluster_snapshot_arns:
            for snapshot_arn in rds_db_cluster_snapshot_arns:
                rds.add_tags_to_resource(ResourceName=snapshot_arn, Tags=[
                    {'Key': 'AutoOwner', 'Value': user},
                    {'Key': 'AutoDate', 'Value': current_date},
                ])

        # Add tags to KMS Keys
        if kms_key_arns:
            for key in kms_key_arns:
                kms.tag_resource(KeyId=key, Tags=[
                    {'TagKey': 'AutoOwner', 'TagValue': user},
                    {'TagKey': 'AutoDate', 'TagValue': current_date},
                ])

        # Add tags to ECS Cluster
        if ecs_cluster_arns:
            for cluster in ecs_cluster_arns:
                ecs.tag_resource(resourceArn=cluster, tags=[
                    {'key': 'AutoOwner', 'value': user},
                    {'key': 'AutoDate', 'value': current_date},
                ])

        # Add tags to ECS task definitions
        if ecs_task_definition_arns:
            for definition in ecs_task_definition_arns:
                ecs.tag_resource(resourceArn=definition, tags=[
                    {'key': 'AutoOwner', 'value': user},
                    {'key': 'AutoDate', 'value': current_date},
                ])

        # Add tags to ECS Service
        if ecs_service_arns:
            for service in ecs_service_arns:
                ecs.tag_resource(resourceArn=service, tags=[
                    {'key': 'AutoOwner', 'value': user},
                    {'key': 'AutoDate', 'value': current_date},
                ])

        # Add tags to EKS Nodegroup
        if eks_nodegroup_arns:
            for nodegroup in eks_nodegroup_arns:
                eks.tag_resource(
                    resourceArn=nodegroup,
                    tags={
                        'AutoOwner': user,
                        'AutoDate': current_date
                    }
                )

        # Add tags to EKS Cluster
        if eks_cluster_arns:
            for cluster in eks_cluster_arns:
                eks.tag_resource(
                    resourceArn=cluster,
                    tags={
                        'AutoOwner': user,
                        'AutoDate': current_date
                    }
                )

    return True
