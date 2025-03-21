# Ansible Network Collection for Keyboard Interactive Auth
<!-- Uncomment these when moved over to my own pipeline
[![CI](https://zuul-ci.org/gated.svg)](https://ansible.softwarefactory-project.io/zuul/builds?project=ansible-collections%2Fansible.netcommon)
[![Codecov](https://codecov.io/gh/ansible-collections/ansible.netcommon/branch/main/graph/badge.svg)](https://codecov.io/gh/ansible-collections/ansible.netcommon)
[![CI](https://github.com/ansible-collections/ansible.netcommon/actions/workflows/tests.yml/badge.svg?branch=main&event=schedule)](https://github.com/ansible-collections/ansible.netcommon/actions/workflows/tests.yml)
-->

The ``evajust.kbd_interactive`` collection is a fork of ``ansible.netcommon`` that handles keyboard interactive authentication with ``paramiko``.
This is to handle connections to network devices that only allow keyboard interactive auth. This collection also communicates with network devices via a pseudo terminal. This is because the devices that caused me to create this collection did not allow ssh command execution.

## Support

This collection is made by me (evajust) for a specific use case. I will be supporting it for my use case, but if you have any issues, I'm open to attempt to fix it if you open an Issue.

I'll also review any PRs that are opened against this repo.

The easiest way to contact me is through Discord: [kbd_interactive](https://discord.gg/U7u9qYpNph)

<!--
## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'network'](https://forum.ansible.com/tag/network): subscribe to participate in collection-related conversations.
  * [Ansible Network Automation Working Group](https://forum.ansible.com/g/network-wg/): by joining the team you will automatically get subscribed to the posts tagged with [network](https://forum.ansible.com/tags/network).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.15.0**.

For collections that support Ansible 2.9, please ensure you update your `network_os` to use the
fully qualified collection name (for example, `cisco.ios.ios`).
Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.

## Included content

### Become plugins
Name | Description
--- | ---
[ansible.netcommon.enable](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.enable_become.rst)|Switch to elevated permissions on a network device

### Cliconf plugins
Name | Description
--- | ---
[ansible.netcommon.default](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.default_cliconf.rst)|General purpose cliconf plugin for new platforms

### Connection plugins
Name | Description
--- | ---
[ansible.netcommon.grpc](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.grpc_connection.rst)|Provides a persistent connection using the gRPC protocol
[ansible.netcommon.httpapi](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.httpapi_connection.rst)|Use httpapi to run command on network appliances
[ansible.netcommon.libssh](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.libssh_connection.rst)|Run tasks using libssh for ssh connection
[ansible.netcommon.netconf](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.netconf_connection.rst)|Provides a persistent connection using the netconf protocol
[ansible.netcommon.network_cli](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.network_cli_connection.rst)|Use network_cli to run command on network appliances
[ansible.netcommon.persistent](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.persistent_connection.rst)|Use a persistent unix socket for connection

### Filter plugins
Name | Description
--- | ---
[ansible.netcommon.comp_type5](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.comp_type5_filter.rst)|The comp_type5 filter plugin.
[ansible.netcommon.hash_salt](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.hash_salt_filter.rst)|The hash_salt filter plugin.
[ansible.netcommon.parse_cli](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.parse_cli_filter.rst)|parse_cli filter plugin.
[ansible.netcommon.parse_cli_textfsm](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.parse_cli_textfsm_filter.rst)|parse_cli_textfsm filter plugin.
[ansible.netcommon.parse_xml](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.parse_xml_filter.rst)|The parse_xml filter plugin.
[ansible.netcommon.pop_ace](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.pop_ace_filter.rst)|Remove ace entries from a acl source of truth.
[ansible.netcommon.type5_pw](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.type5_pw_filter.rst)|The type5_pw filter plugin.
[ansible.netcommon.vlan_expander](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.vlan_expander_filter.rst)|The vlan_expander filter plugin.
[ansible.netcommon.vlan_parser](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.vlan_parser_filter.rst)|The vlan_parser filter plugin.

### Httpapi plugins
Name | Description
--- | ---
[ansible.netcommon.restconf](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.restconf_httpapi.rst)|HttpApi Plugin for devices supporting Restconf API

### Netconf plugins
Name | Description
--- | ---
[ansible.netcommon.default](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.default_netconf.rst)|Use default netconf plugin to run standard netconf commands as per RFC

### Modules
Name | Description
--- | ---
[ansible.netcommon.cli_backup](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.cli_backup_module.rst)|Back up device configuration from network devices over network_cli
[ansible.netcommon.cli_command](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.cli_command_module.rst)|Run a cli command on cli-based network devices
[ansible.netcommon.cli_config](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.cli_config_module.rst)|Push text based configuration to network devices over network_cli
[ansible.netcommon.cli_restore](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.cli_restore_module.rst)|Restore device configuration to network devices over network_cli
[ansible.netcommon.grpc_config](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.grpc_config_module.rst)|Fetch configuration/state data from gRPC enabled target hosts.
[ansible.netcommon.grpc_get](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.grpc_get_module.rst)|Fetch configuration/state data from gRPC enabled target hosts.
[ansible.netcommon.net_get](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.net_get_module.rst)|Copy a file from a network device to Ansible Controller
[ansible.netcommon.net_ping](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.net_ping_module.rst)|Tests reachability using ping from a network device
[ansible.netcommon.net_put](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.net_put_module.rst)|Copy a file from Ansible Controller to a network device
[ansible.netcommon.netconf_config](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.netconf_config_module.rst)|netconf device configuration
[ansible.netcommon.netconf_get](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.netconf_get_module.rst)|Fetch configuration/state data from NETCONF enabled network devices.
[ansible.netcommon.netconf_rpc](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.netconf_rpc_module.rst)|Execute operations on NETCONF enabled network devices.
[ansible.netcommon.network_resource](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.network_resource_module.rst)|Manage resource modules
[ansible.netcommon.restconf_config](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.restconf_config_module.rst)|Handles create, update, read and delete of configuration data on RESTCONF enabled devices.
[ansible.netcommon.restconf_get](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.restconf_get_module.rst)|Fetch configuration/state data from RESTCONF enabled devices.
[ansible.netcommon.telnet](https://github.com/ansible-collections/ansible.netcommon/blob/main/docs/ansible.netcommon.telnet_module.rst)|Executes a low-down and dirty telnet command

-->

## Installing this collection

You can install the ``evajust.kbd_interactive`` collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install evajust.kbd_interactive

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: evajust.kbd_interactive
```

<!--
## Using this collection

The most common use case for this collection is to include it as a dependency in a network device-specific collection. Use the Fully Qualified Collection Name (FQCN) when referring to content in this collection (for example, `ansible.netcommon.network_cli`).

See the [Vyos collection](https://github.com/ansible-collections/vyos.vyos) for an example of this.

### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [ansible.netcommon collection repository](https://github.com/ansible-collections/ansible.netcommon). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - ``#ansible-network`` [irc.libera.chat](https://libera.chat/) channel
- Slack - https://ansiblenetwork.slack.com

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.


## Release notes

Release notes are available [here](https://github.com/ansible-collections/ansible.netcommon/blob/main/CHANGELOG.rst)

## More information

- [Developing network resource modules](https://docs.ansible.com/ansible/latest/network/dev_guide/developing_resource_modules_network.html#developing-resource-modules)
- [Ansible network resources](https://docs.ansible.com/ansible/latest/network/getting_started/network_resources.html)
- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
-->
