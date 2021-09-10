import os
import boto3
import requests


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
    if "." in address:
        rulekey = 'IpRanges'
        rangekey = 'CidrIp'
    else:
        rulekey = 'Ipv6Ranges'
        rangekey = 'CidrIpv6'
    for rule in rules:
        for ip_range in rule[rulekey]:
            if ip_range[rangekey] == address and rule['FromPort'] == port:
                return True
    return False



def add_ingress_rule(group, address, port, description):
    """
    Add the IP address and port to the security group

    :param group:
    :param address:
    :param port:
    :param description:
    :return:
    """
    if "." in address:
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
    else:
        permissions = [
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'Ipv6Ranges': [
                    {
                        'CidrIpv6': address,
                        'Description': description,
                    }
                ],
            }
        ]
    group.authorize_ingress(IpPermissions=permissions)
    print(("Ingress rule from IP %s to Port %i has been added" % (address, port)))


def add_egress_rule(group, address, port, description):
    """
    Add the IP address and port to the security group

    :param group:
    :param address:
    :param port:
    :param description:
    :return:
    """
    if "." in address:
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
    else:
        permissions = [
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'Ipv6Ranges': [
                    {
                        'CidrIpv6': address,
                        'Description': description,
                    }
                ],
            }
        ]
    group.authorize_egress(IpPermissions=permissions)
    print(("Egress rule to IP %s from Port %i has been added" % (address, port)))


def lambda_handler(event, context):
    """
    AWS lambda main func

    :param event:
    :param context:
    :return:
    """
    ingress_ports = [int(port) for port in os.environ['INGRESS_PORTS_LIST'].split(",")]
    if not ingress_ports:
        ingress_ports = [80]

    egress_ports = [int(port) for port in os.environ['EGRESS_PORTS_LIST'].split(",")]
    if not egress_ports:
        egress_ports = [22]

    security_group = get_aws_security_group(os.environ['SECURITY_GROUP_ID'])
    current_ingress_rules = security_group.ip_permissions
    current_egress_rules = security_group.ip_permissions_egress
    ip_addresses = get_github_ip_list()
    description = "GitHub"

    for ip_address in ip_addresses:
        for port in ingress_ports:
            if not check_rule_exists(current_ingress_rules, ip_address, port):
                add_ingress_rule(security_group, ip_address, port, description)
        for port in egress_ports:
            if not check_rule_exists(current_egress_rules, ip_address, port):
                add_egress_rule(security_group, ip_address, port, description)