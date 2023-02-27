#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import requests
import json

DOCUMENTATION = """
---
module: wazuh_group
short_description: Manage groups in Wazuh using the Wazuh API
description:  Manage groups in Wazuh using the Wazuh API
author:
    - Simon Bärlocher (@sbaerlocher)
    - Open Circle AG (@occ)
options:
  state:
    description:
      - Whether the group should be present or absent
    required: false
    default: present
    choices: [present, absent]
  group_id:
    description:
      - The name of the group
    required: true
  api_endpoint:
    description:
      - The URL of the Wazuh API endpoint
    required: true
  api_user:
    description:
      - The username to use for Wazuh API authentication
    required: true
  api_password:
    description:
      - The password to use for Wazuh API authentication
    required: true
  token_expire_time:
    description:
      - The amount of time, in seconds, before the authentication token expires
    required: false
    default: 900
    type: int
"""

EXAMPLES = """
- name: Create a group
  wazuh_group:
    group_id: my_new_group
    wazuh_api_endpoint: https://wazuh.example.com:55000/
    wazuh_api_user: wazuh_admin
    wazuh_api_password: mysecretpassword
  register: result

- name: Delete a group
  wazuh_group:
    state: absent
    group_id: my_new_group
    wazuh_api_endpoint: https://wazuh.example.com:55000/
    wazuh_api_user: wazuh_admin
    wazuh_api_password: mysecretpassword
  register: result
"""

def get_auth_token(api_url, username, password, token_expire_time=900):
    """Authenticate with Wazuh API and retrieve a JWT token"""
    token_url = f"{api_url}security/user/authenticate"
    auth = requests.auth.HTTPBasicAuth(username, password)

    # Get JWT token
    response = requests.get(token_url, auth=auth, verify=False)
    if response.status_code != 200:
        raise Exception(f"Error retrieving JWT token: {response.status_code}")
    token = response.json()["data"]["token"]

    return token

def create_group(group_id, wazuh_api_endpoint, wazuh_api_token):
    """
    Creates a group in Wazuh using the Wazuh API
    """
    
    headers = {'Content-type': 'application/json', 'Authorization': f'Bearer {wazuh_api_token}'}
    url = '{}/groups'.format(wazuh_api_endpoint)
    data = {'group_id': group_id}

    response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)

    if response.status_code != 200:
        raise Exception('Failed to create group: {} ({})'.format(response.text, response.status_code))

    return response.json()

def delete_group(group_id, wazuh_api_endpoint, wazuh_api_token):
    """
    Deletes a group in Wazuh using the Wazuh API
    """

    url = '{}/groups/?groups_list={}'.format(wazuh_api_endpoint, group_id)
    headers = {'Authorization': f'Bearer {wazuh_api_token}'}

    response = requests.delete(url, headers=headers, verify=False)

    if response.status_code != 200:
        raise Exception('Failed to delete group: {} ({})'.format(response.text, response.status_code))

def exist_group(group_id, wazuh_api_endpoint, wazuh_api_token):
    """
    Check if the group with the specified name exists in Wazuh
    """
    headers = {"Authorization": f"Bearer {wazuh_api_token}"}
    url = f"{wazuh_api_endpoint}groups"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code != 200:
        raise Exception(f"Error retrieving group list: {response.status_code}")

    for group in response.json().get("data", {}).get("affected_items", []):
        if group['name'] == group_id:
            return True

    return False

def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent']),
            group_id=dict(required=True),
            wazuh_api_endpoint=dict(required=True),
            wazuh_api_user=dict(required=True),
            wazuh_api_password=dict(required=True, no_log=True),
            token_expire_time=dict(type='int', default=900)
        ),
        supports_check_mode=True
    )

    state = module.params['state']
    group_id = module.params['group_id']
    wazuh_api_endpoint = module.params['wazuh_api_endpoint']
    wazuh_api_user = module.params['wazuh_api_user']
    wazuh_api_password = module.params['wazuh_api_password']
    token_expire_time = module.params['token_expire_time']

    try:
        # Get auth token
        token = get_auth_token(wazuh_api_endpoint, wazuh_api_user, wazuh_api_password, token_expire_time)

        if state == 'present':
                if not exist_group(group_id, wazuh_api_endpoint, token):
                    group = create_group(group_id, wazuh_api_endpoint, token)
                    module.exit_json(changed=True, group=group)
                else:
                    module.exit_json(changed=False, group_id=group_id)
        elif state == 'absent':
                if exist_group(group_id, wazuh_api_endpoint, token):
                    delete_group(group_id, wazuh_api_endpoint, token)
                    module.exit_json(changed=True, group_id=group_id)
                else:
                    module.exit_json(changed=False)
    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
