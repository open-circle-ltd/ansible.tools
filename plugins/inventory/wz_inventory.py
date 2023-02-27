#!/usr/bin/python

import requests
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable

__metaclass__ = type

DOCUMENTATION = """
    name: wazuh
    plugin_type: inventory
    short_description: Wazuh Inventory Source
    description: Generates an Ansible inventory from hosts in a Wazuh server using the Wazuh API.
    extends_documentation_fragment:
        - constructed
    author:
        - Simon Bärlocher (@sbaerlocher)
        - Open Circle AG (@occ)
    options:
        api_endpoint:
            description: URL of the Wazuh API endpoint.
            type: string
            required: true
            env:
                - name: WAZUH_API_ENDPOINT
        api_user:
            description: Username to authenticate with the Wazuh API.
            type: string
            required: true
            env:
                - name: WAZUH_API_USER
        api_password:
            description: Password to authenticate with the Wazuh API.
            type: string
            required: true
            env:
                - name: WAZUH_API_PASSWORD
        filter_by_groups:
            description: A list of Wazuh groups to include in the inventory.
            type: list
            elements: string
            required: false
        ansible_host_order:
            description:
            type: list
            elements: string
            required: false
            default: []
        ansible_host:
            description: set the ansible_host to which value?
            required: false
            choices: ['ipv4','ipv6']
            default: ipv4
"""

class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = 'wazuh'

    def __init__(self):
        super(InventoryModule, self).__init__()

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)

        # Get Wazuh API endpoint and credentials from inventory file
        wazuh_api_endpoint = self.get_option('api_endpoint')
        wazuh_api_user = self.get_option('api_user')
        wazuh_api_password = self.get_option('api_password')
        filter_by_groups = self.get_option('filter_by_groups')
        ansible_host_order = self.get_option('ansible_host_order')

        # Authenticate with Wazuh API and retrieve a JWT token
        token_url = f"{wazuh_api_endpoint}security/user/authenticate"
        auth = requests.auth.HTTPBasicAuth(wazuh_api_user, wazuh_api_password)


        response = requests.get(token_url, auth=auth, verify=True)

        if response.status_code != 200:
            raise Exception(f"Error retrieving JWT token: {response.status_code}")
        token = response.json()["data"]["token"]

        agents = []
        if filter_by_groups is None:
            filter_by_groups = ['']
        for group in filter_by_groups:
        # Get all agents from Wazuh API and add them to the inventory
            agents_url = f"{wazuh_api_endpoint}agents?limit=100000&group={group}"
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(agents_url, headers=headers, verify=True)
            if response.status_code != 200:
                raise Exception(f"Error retrieving agents: {response.status_code}")
            agents.extend(response.json().get("data", {}).get("affected_items", []))


        for agent in agents:
            hostname = agent.get("name")
         
            for group in agent.get('group', []):
                if group != 'default':
                    self.inventory.add_group(group.replace("-", "_"))
                    self.inventory.add_host(hostname, group.replace("-", "_"))

            self.inventory.set_variable(hostname, 'status', agent.get('status'))
            self.inventory.set_variable(hostname, 'agent_id', agent.get('id'))

            if ansible_host_order:
                syscollector_url = f"{wazuh_api_endpoint}syscollector/{agent.get('id')}/netaddr"
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(syscollector_url, headers=headers, verify=True)
                if response.status_code != 200:
                    raise Exception(f"Error retrieving syscollector: {response.status_code}")

                netaddr_list = [d for _, d in sorted([(d['iface'], d) for d in response.json().get("data", {}).get("affected_items", [])], key=lambda x: ansible_host_order.index(x[0]) if x[0] in ansible_host_order else len(ansible_host_order))]
                if netaddr_list:
                    ansible_host = self.get_option("ansible_host")
                    if ansible_host == 'ipv4':
                        ipv4_list = [elem for elem in netaddr_list if elem.get('proto') == 'ipv4']
                        self.inventory.set_variable(hostname, "ansible_host", ipv4_list[0].get('address'))
                    else:
                        ipv6_list = [elem for elem in netaddr_list if elem.get('proto') == 'ipv6']
                        self.inventory.set_variable(hostname, "ansible_host", ipv6_list[0].get('address'))
                        
            else:
                self.inventory.set_variable(hostname, "ansible_host", agent.get("ip"))

            # Use constructed if applicable
            strict = self.get_option('strict')

            # Composed variables
            self._set_composite_vars(self.get_option('compose'), self.inventory.get_host(hostname).get_vars(), hostname, strict=strict)

            # Complex groups based on jinja2 conditionals, hosts that meet the conditional are added to group
            self._add_host_to_composed_groups(self.get_option('groups'), {}, hostname, strict=strict)

            # Create groups based on variable values and add the corresponding hosts to it
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), {}, hostname, strict=strict)

    def get_vars(self, host):
        return self._inventory.get(host, {})

    def list_hosts(self):
        return list(self._inventory.keys())

    def _match(self, hostname, pattern):
        return self.inventory.matches(pattern, hostname)

    def refresh_inventory(self):
        pass
