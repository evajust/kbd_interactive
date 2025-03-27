# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import annotations

DOCUMENTATION = """
    author: Ansible Core Team
    name: kbd_interactive
    short_description: Run tasks via Python SSH (paramiko)
    description:
        - Use the Python SSH implementation (Paramiko) to connect to targets
        - The paramiko transport is provided because many distributions, in particular EL6 and before do not support ControlPersist
          in their SSH implementations.
        - This is needed on the Ansible control machine to be reasonably efficient with connections.
          Thus paramiko is faster for most users on these platforms.
          Users with ControlPersist capability can consider using -c ssh or configuring the transport in the configuration file.
        - This plugin also borrows a lot of settings from the ssh plugin as they both cover the same protocol.
    version_added: "0.1.0"
    options:
      remote_addr:
        description:
            - Address of the remote target
        default: inventory_hostname
        type: string
        vars:
            - name: inventory_hostname
            - name: ansible_host
            - name: ansible_ssh_host
            - name: ansible_paramiko_host
      port:
          description: Remote port to connect to.
          type: int
          default: 22
          ini:
            - section: defaults
              key: remote_port
            - section: paramiko_connection
              key: remote_port
              version_added: '2.15.0'
          env:
            - name: ANSIBLE_REMOTE_PORT
            - name: ANSIBLE_REMOTE_PARAMIKO_PORT
              version_added: '2.15.0'
          vars:
            - name: ansible_port
            - name: ansible_ssh_port
            - name: ansible_paramiko_port
              version_added: '2.15.0'
          keyword:
            - name: port
      remote_user:
        description:
            - User to login/authenticate as
            - Can be set from the CLI via the C(--user) or C(-u) options.
        type: string
        vars:
            - name: ansible_user
            - name: ansible_ssh_user
            - name: ansible_paramiko_user
        env:
            - name: ANSIBLE_REMOTE_USER
            - name: ANSIBLE_PARAMIKO_REMOTE_USER
              version_added: '2.5.0'
        ini:
            - section: defaults
              key: remote_user
            - section: paramiko_connection
              key: remote_user
              version_added: '2.5.0'
        keyword:
            - name: remote_user
      password:
        description:
          - Secret used to either login the ssh server or as a passphrase for ssh keys that require it
          - Can be set from the CLI via the C(--ask-pass) option.
        type: string
        vars:
            - name: ansible_password
            - name: ansible_ssh_pass
            - name: ansible_ssh_password
            - name: ansible_paramiko_pass
            - name: ansible_paramiko_password
              version_added: '2.5.0'
      use_rsa_sha2_algorithms:
        description:
            - Whether or not to enable RSA SHA2 algorithms for pubkeys and hostkeys
            - On paramiko versions older than 2.9, this only affects hostkeys
            - For behavior matching paramiko<2.9 set this to V(False)
        vars:
            - name: ansible_paramiko_use_rsa_sha2_algorithms
        ini:
            - {key: use_rsa_sha2_algorithms, section: paramiko_connection}
        env:
            - {name: ANSIBLE_PARAMIKO_USE_RSA_SHA2_ALGORITHMS}
        default: True
        type: boolean
        version_added: '2.14.0'
      host_key_auto_add:
        description: 'Automatically add host keys'
        env: [{name: ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD}]
        ini:
          - {key: host_key_auto_add, section: paramiko_connection}
        type: boolean
      look_for_keys:
        default: True
        description: 'False to disable searching for private key files in ~/.ssh/'
        env: [{name: ANSIBLE_PARAMIKO_LOOK_FOR_KEYS}]
        ini:
        - {key: look_for_keys, section: paramiko_connection}
        type: boolean
      proxy_command:
        default: ''
        description:
            - Proxy information for running the connection via a jumphost.
        type: string
        env: [{name: ANSIBLE_PARAMIKO_PROXY_COMMAND}]
        ini:
          - {key: proxy_command, section: paramiko_connection}
        vars:
          - name: ansible_paramiko_proxy_command
            version_added: '2.15.0'
      pty:
        default: True
        description: 'SUDO usually requires a PTY, True to give a PTY and False to not give a PTY.'
        env:
          - name: ANSIBLE_PARAMIKO_PTY
        ini:
          - section: paramiko_connection
            key: pty
        type: boolean
      record_host_keys:
        default: True
        description: 'Save the host keys to a file'
        env: [{name: ANSIBLE_PARAMIKO_RECORD_HOST_KEYS}]
        ini:
          - section: paramiko_connection
            key: record_host_keys
        type: boolean
      host_key_checking:
        description: 'Set this to "False" if you want to avoid host key checking by the underlying tools Ansible uses to connect to the host'
        type: boolean
        default: True
        env:
          - name: ANSIBLE_HOST_KEY_CHECKING
          - name: ANSIBLE_SSH_HOST_KEY_CHECKING
            version_added: '2.5.0'
          - name: ANSIBLE_PARAMIKO_HOST_KEY_CHECKING
            version_added: '2.5.0'
        ini:
          - section: defaults
            key: host_key_checking
          - section: paramiko_connection
            key: host_key_checking
            version_added: '2.5.0'
        vars:
          - name: ansible_host_key_checking
            version_added: '2.5.0'
          - name: ansible_ssh_host_key_checking
            version_added: '2.5.0'
          - name: ansible_paramiko_host_key_checking
            version_added: '2.5.0'
      use_persistent_connections:
        description: 'Toggles the use of persistence for connections'
        type: boolean
        default: False
        env:
          - name: ANSIBLE_USE_PERSISTENT_CONNECTIONS
        ini:
          - section: defaults
            key: use_persistent_connections
      banner_timeout:
        type: float
        default: 30
        version_added: '2.14.0'
        description:
          - Configures, in seconds, the amount of time to wait for the SSH
            banner to be presented. This option is supported by paramiko
            version 1.15.0 or newer.
        ini:
          - section: paramiko_connection
            key: banner_timeout
        env:
          - name: ANSIBLE_PARAMIKO_BANNER_TIMEOUT
      timeout:
        type: int
        default: 10
        description: Number of seconds until the plugin gives up on failing to establish a TCP connection.
        ini:
          - section: defaults
            key: timeout
          - section: ssh_connection
            key: timeout
            version_added: '2.11.0'
          - section: paramiko_connection
            key: timeout
            version_added: '2.15.0'
        env:
          - name: ANSIBLE_TIMEOUT
          - name: ANSIBLE_SSH_TIMEOUT
            version_added: '2.11.0'
          - name: ANSIBLE_PARAMIKO_TIMEOUT
            version_added: '2.15.0'
        vars:
          - name: ansible_ssh_timeout
            version_added: '2.11.0'
          - name: ansible_paramiko_timeout
            version_added: '2.15.0'
        cli:
          - name: timeout
      private_key_file:
          description:
              - Path to private key file to use for authentication.
          type: string
          ini:
            - section: defaults
              key: private_key_file
            - section: paramiko_connection
              key: private_key_file
              version_added: '2.15.0'
          env:
            - name: ANSIBLE_PRIVATE_KEY_FILE
            - name: ANSIBLE_PARAMIKO_PRIVATE_KEY_FILE
              version_added: '2.15.0'
          vars:
            - name: ansible_private_key_file
            - name: ansible_ssh_private_key_file
            - name: ansible_paramiko_private_key_file
              version_added: '2.15.0'
          cli:
            - name: private_key_file
              option: '--private-key'
      auth_interactive_prompt_username:
        description:
        - The prompt to expect when passing the username for keyboard interactive
          auth.
        type: string
        vars:
        - name: auth_interactive_prompt_username
      auth_interactive_prompt_password:
        description:
        - The prompt to expect when passing the password for keyboard interactive
          auth.
        type: string
        vars:
        - name: auth_interactive_prompt_password
"""

import socket
import time

from ansible.errors import (
    AnsibleAuthenticationFailure,
    AnsibleConnectionFailure,
    AnsibleError,
)
from ansible.module_utils.compat.paramiko import PARAMIKO_IMPORT_ERR, paramiko
from ansible.plugins.connection.paramiko_ssh import Connection as ParamikoConnection
from ansible.utils.display import Display
from ansible.module_utils.common.text.converters import to_native, to_text

display = Display()


SSH_CONNECTION_CACHE: dict[str, paramiko.client.SSHClient] = {}


class Connection(ParamikoConnection):
    ''' SSH based connections with Paramiko '''

    def inter_handler(self, title, instructions, prompt_list):

        resp = []

        password_prompt = self.get_option('auth_interactive_prompt_password')
        for pr in prompt_list:
            prompt = str(pr[0]).strip()
            if prompt == password_prompt:
                resp.append(self.get_option('password'))

        return resp

    def _connect_uncached(self) -> paramiko.SSHClient:
        ''' activates the connection object '''

        if paramiko is None:
            raise AnsibleError("paramiko is not installed: %s" % to_native(PARAMIKO_IMPORT_ERR))

        username = self.get_option('remote_user')

        node = self.get_option('remote_addr').lower()
        port = self.get_option('port')
        display.vvv("ESTABLISH PARAMIKO SSH CONNECTION FOR USER: %s on PORT %s TO %s" % (self.get_option('remote_user'), port, self.get_option('remote_addr')),
                    host=self.get_option('remote_addr'))

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((node, 22))

            self.ts = paramiko.Transport(sock)
            self.ts.packetizer._Packetizer__dump_packets = True
            self.ts.start_client(timeout=10)
            self.ts.auth_interactive(username, self.inter_handler)

            chan = self.ts.open_session(timeout=10)
            chan.get_pty()

            time.sleep(1)
        except paramiko.ssh_exception.AuthenticationException as e:
            msg = 'Failed to authenticate: {0}'.format(to_text(e))
            raise AnsibleAuthenticationFailure(msg)
        except Exception as e:
            msg = to_text(e)
            if u"PID check failed" in msg:
                raise AnsibleError("paramiko version issue, please upgrade paramiko on the machine running ansible")
            elif u"Private key file is encrypted" in msg:
                msg = 'ssh %s@%s:%s : %s\nTo connect as a different user, use -u <username>.' % (
                    self.get_option('remote_user'), self.get_options('remote_addr'), port, msg)
                raise AnsibleConnectionFailure(msg)
            else:
                raise AnsibleConnectionFailure(msg)

        return chan

    def close(self) -> None:
        ''' terminate the connection '''

        cache_key = self._cache_key()
        SSH_CONNECTION_CACHE.pop(cache_key, None)

        self.ssh.close()
        self._connected = False
