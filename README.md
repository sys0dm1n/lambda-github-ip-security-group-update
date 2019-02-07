# lambda-github-ip-security-group-update

Using a Lambda function to automate creating and updating a Security Group of GitHub's hooks IP addresses.
I use this function to only allow Github webhooks access my Jenkins instance hosted on AWS ec2 instance.

## Configure triggers using CloudWatch Events

* Schedule expression: rate(1 day)
* Enabled
    
## Function code for GitHub

* **Python** 2.7

## Environment variables

**key:** PORTS_LIST
**value:** 8001,8002

**key:** SECURITY_GROUP_ID
**value:** add your security group id here

If required you can create a custom security group using the below command line:

    aws ec2 create-security-group --group-name github-access --description "GitHub IPs access" --vpc-id VPC-ID-GOES-HERE

## Create a custom role

* **Role Name:** XXXXX-ip-security-group-update

Required rule to allow the lambda function to edit the security group, use the content of the _allow-ec2-security-group_ file       

## Time out

Set the Timeout to 8 seconds
    
**Ref.:** 

* [https://api.github.com/meta](https://api.github.com/meta)
* [https://help.github.com/articles/about-github-s-ip-addresses/](https://help.github.com/articles/about-github-s-ip-addresses/)

