import os
import boto3
from botocore.vendored import requests


def get_github_ip_list():
    """
    Call the GitHub API to fetch their server IPs used for webhooks

    :rtype: list
    :return: List of IPs
    """
    response = requests.get('https://api.github.com/meta')
    ips = response.json()
    if 'hooks' in ips:
        return ips['hooks']

    raise ConnectionError("Error loading IPs from GitHub")


def get_aws_security_group(group_id):
    """
    Return the defined Security Group

    :param group_id:
    :type group_id: str
    :return:
    """
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    if group.group_id == group_id:
        return group

    raise ConnectionError('Failed to retrieve security group from Amazon')


def check_rule_exists(rules, address, port):
    """
    Check if the rule currently exists

    :param rules:
    :param address:
    :param port:
    :return:
    """
    for rule in rules:
        for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] == address and rule['FromPort'] == port:
                return True
    return False


def add_rule(group, address, port, description):
    """
    Add the IP address and port to the security group

    :param group:
    :param address:
    :param port:
    :param description:
    :return:
    """
    permissions = [
        {
            'IpProtocol': 'tcp',
            'FromPort': port,
            'ToPort': port,
            'IpRanges': [
                {
                    'CidrIp': address,
                    'Description': description,
                }
            ],
        }
    ]
    group.authorize_ingress(IpPermissions=permissions)
    print("Added %s : %i  " % (address, port))


def lambda_handler(event, context):
    """
    AWS lambda main func

    :param event:
    :param context:
    :return:
    """
    ports = [int(port) for port in os.environ['PORTS_LIST'].split(",")]
    if not ports:
        ports = [80]

    security_group = get_aws_security_group(os.environ['SECURITY_GROUP_ID'])
    current_rules = security_group.ip_permissions
    ip_addresses = get_github_ip_list()
    description = "Authorize GitHub webhooks access"

    for ip_address in ip_addresses:
        for port in ports:
            if not check_rule_exists(current_rules, ip_address, port):
                add_rule(security_group, ip_address, port, description)
