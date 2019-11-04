# lambda-github-ip-security-group-update

Using a Lambda function to automate creating and updating a Security Group of GitHub's hooks IP addresses.
I use this function to only allow Github webhooks access my Jenkins instance hosted on AWS ec2 instance.

## Configure triggers using CloudWatch Events

* Schedule expression: rate(1 day)
* Enabled
    
## Function code for GitHub

* **Python** 3.7

## Environment variables

**key:** INGRESS_PORTS_LIST
**value:** 80,443

**key:** EGRESS_PORTS_LIST
**value:** 22,80,443

**key:** SECURITY_GROUP_ID
**value:** add your security group id here

If required you can create a custom security group using the below command line:

    aws ec2 create-security-group --group-name github-access --description "GitHub IPs access" --vpc-id VPC-ID-GOES-HERE

## Create a custom role

* **Role Name:** github-ip-security-group-update

Required rule to allow the lambda function to edit the security group, use the content of the _allow-ec2-security-group-role_ file       

## Time out

Set the Timeout to 8 seconds
    
## Room for improvement

If you happen to find something not to your liking, you are welcome to send a PR.

**Ref.:** 

* [https://api.github.com/meta](https://api.github.com/meta)
* [https://help.github.com/articles/about-github-s-ip-addresses/](https://help.github.com/articles/about-github-s-ip-addresses/)

