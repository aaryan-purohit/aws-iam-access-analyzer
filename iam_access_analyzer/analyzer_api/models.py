from django.db import models
import boto3
import re
# Create your models here.

client = boto3.client('iam')


# function to list users
def list_user_names():
    """List Users"""
    users = client.list_users()
    username = []
    for user in users['Users']:
        username.append(user['UserName'])
    return username

## function to retrive inline policies documents attached to users
def user_inline_policies_document():
    """Inline Policy Documents"""

    users = list_user_names()
    
    # dictionary for attaching inline/managed policiy to individual user
    user_policy_dict = {}
    
    for user in users:
        
        # get inline policies attached to the specific user
        inline_policies = client.list_user_policies(UserName=user)
        
        inline_policy_document = []

        # if list of policy names not empty
        if inline_policies['PolicyNames']:
            
            for policy_name in inline_policies['PolicyNames']:
                
                inline_policy_document.append(client.get_user_policy(UserName=user, PolicyName=policy_name))
                # print(inline_policy_document)

                for item in inline_policy_document:


                    user_policy_dict[user] = [{
                        'PolicyName': item['PolicyName'],
                        'PolicyDocument': item['PolicyDocument']
                    }]
    
    return user_policy_dict


## function to retirve policies attached to user
def user_attached_policy_documents():
    """Policies Attacched to user"""

    users = list_user_names()
    
    # dictionary for attaching managed policiy to individual user
    user_policy_dict = {}
    
    for user in users:
                
        # retrieved attached customer managed policies
        attached_policies = client.list_attached_user_policies(UserName=user)  

        # if list not empty
        if(attached_policies['AttachedPolicies']):
            for item in attached_policies['AttachedPolicies']:

                
                resource = item['PolicyArn']

                # regular expression to filter policy based on arn attached to the account
                m = re.match(r'^arn:aws:iam::(\d{12})?:policy/[\w+=,.@-]{1,128}$', resource)

                if m:
                    # print(user)

                    # retrieve policy versions
                    response = client.list_policy_versions(PolicyArn = item['PolicyArn'])
                    
                    arn = item['PolicyArn']
                    version = response['Versions']

                    # retrive policy document for each version
                    for id in version:
                        document = client.get_policy_version(PolicyArn=arn, VersionId=id['VersionId'])
                        
                        user_policy_dict[user] = [{
                            'attached_policy_details': [{
                                'PolicyName': item['PolicyName'],
                                'PolicyArn': arn,
                                'PolicyDocument': document
                            }] 
                        }]
                        # print(user_policy_dict)
                    #     print()
                    # print()

                
    return user_policy_dict


# Function to Analyze the access of inline policy for users
def access_analyzer_inline_policy_for_users():
    """Inline access analyzer for User Policies"""

    inline_policy_documents = user_inline_policies_document()
    # print(inline_policy_documents)

    # retrieve keys present in inline policy document dictionary
    keys = inline_policy_documents.keys()

    inline_resource_alert = {}
    inline_access_action_alert = {}

    for key in keys:

        document_list = inline_policy_documents[key]
        
        for list in document_list:
          
            for item in list['PolicyDocument']['Statement']:

                # iteratate over action to find the policy which violates
                for action in item['Action']:
                    if re.match(r"\w+:\*", action):
                        print("action = " ,action)
                        inline_access_action_alert[key] = [{
                            'Policy_Name' : list['PolicyName'],
                            'Version': list['PolicyDocument']['Version'],
                            'Statement': list['PolicyDocument']['Statement']
                        }]
                    
                
                # if match found then return report of the inline policy which violates the rules
                if (item['Resource'] == '*'):

                    inline_resource_alert[key] = [{
                        'Policy_Name' : list['PolicyName'],
                        'Version': list['PolicyDocument']['Version'],
                        'Statement': list['PolicyDocument']['Statement']
                    }]


    return inline_resource_alert, inline_access_action_alert



# function to analyze the access of customer managed policy for users
def access_analyzer_custom_manage_policy_for_users():
    """Customer managed Access Analyzer for user Polcies"""

    attached_policy_docuemnts = user_attached_policy_documents()

    # get user names
    keys = attached_policy_docuemnts.keys()

    managed_resource_alert = {}
    managed_action_alert = {}

    for key in keys:
        
        for policy_details in attached_policy_docuemnts[key]:
            
            for policy in policy_details['attached_policy_details']:
                
                for item in policy['PolicyDocument']['PolicyVersion']['Document']['Statement']:
                
                    # if resource match found then return report of the managed policy which violates the rules
                    if (item['Resource'] == '*'):
                        managed_resource_alert[key] = [{
                            'PolicyName': policy['PolicyName'],
                            'PolicyArn': policy['PolicyArn'],
                            'Version': policy['PolicyDocument']['PolicyVersion']['Document']['Version'],
                            'Statement': policy['PolicyDocument']['PolicyVersion']['Document']['Statement']
                        }]

                    # iteratate over action to find the policy which violates
                    for action in item['Action']:
                        if re.match(r"\w+:\*", action):
                            # print("action = " ,action)

                            managed_action_alert[key] = [{
                            'PolicyName': policy['PolicyName'],
                            'PolicyArn': policy['PolicyArn'],
                            'Version': policy['PolicyDocument']['PolicyVersion']['Document']['Version'],
                            'Action': action
                            }]


                
                

    return managed_resource_alert, managed_action_alert

if __name__ == "__main__":

    # User Policies
    inline_resource_alert, inline_access_action_alert = access_analyzer_inline_policy_for_users()
    print(inline_resource_alert)
    print(inline_access_action_alert)

    # managed_resource_alert, managed_action_alert = access_analyzer_custom_manage_policy_for_users()
    # print(managed_resource_alert)
    # print()
    # print(managed_action_alert)


## resource : * kisi bhi server pr chl jayega na