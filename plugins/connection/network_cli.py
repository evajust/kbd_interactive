# (c) 2016 Red Hat Inc.
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author:
 - Ansible Networking Team (@ansible-network)
name: network_cli
short_description: Use network_cli to run command on network appliances
description:
- This connection plugin provides a connection to remote devices over the SSH and
  implements a CLI shell.  This connection plugin is typically used by network devices
  for sending and receiving CLi commands to network devices.
version_added: 1.0.0
requirements:
- ansible-pylibssh if using I(ssh_type=libssh)
extends_documentation_fragment:
- ansible.netcommon.connection_persistent
options:
  host:
    description:
    - Specifies the remote device FQDN or IP address to establish the SSH connection
      to.
    default: inventory_hostname
    type: string
    vars:
    - name: inventory_hostname
    - name: ansible_host
  port:
    type: int
    description:
    - Specifies the port on the remote device that listens for connections when establishing
      the SSH connection.
    default: 22
    ini:
    - section: defaults
      key: remote_port
    env:
    - name: ANSIBLE_REMOTE_PORT
    vars:
    - name: ansible_port
  network_os:
    description:
    - Configures the device platform network operating system.  This value is used
      to load the correct terminal and cliconf plugins to communicate with the remote
      device.
    type: string
    vars:
    - name: ansible_network_os
  remote_user:
    description:
    - The username used to authenticate to the remote device when the SSH connection
      is first established.  If the remote_user is not specified, the connection will
      use the username of the logged in user.
    - Can be configured from the CLI via the C(--user) or C(-u) options.
    type: string
    ini:
    - section: defaults
      key: remote_user
    env:
    - name: ANSIBLE_REMOTE_USER
    vars:
    - name: ansible_user
  password:
    description:
    - Configures the user password used to authenticate to the remote device when
      first establishing the SSH connection.
    type: string
    vars:
    - name: ansible_password
    - name: ansible_ssh_pass
    - name: ansible_ssh_password
  private_key_file:
    description:
    - The private SSH key or certificate file used to authenticate to the remote device
      when first establishing the SSH connection.
    type: string
    ini:
    - section: defaults
      key: private_key_file
    env:
    - name: ANSIBLE_PRIVATE_KEY_FILE
    vars:
    - name: ansible_private_key_file
  become:
    type: boolean
    description:
    - The become option will instruct the CLI session to attempt privilege escalation
      on platforms that support it.  Normally this means transitioning from user mode
      to C(enable) mode in the CLI session. If become is set to True and the remote
      device does not support privilege escalation or the privilege has already been
      elevated, then this option is silently ignored.
    - Can be configured from the CLI via the C(--become) or C(-b) options.
    default: false
    ini:
    - section: privilege_escalation
      key: become
    env:
    - name: ANSIBLE_BECOME
    vars:
    - name: ansible_become
  become_errors:
    type: str
    description:
    - This option determines how privilege escalation failures are handled when
      I(become) is enabled.
    - When set to C(ignore), the errors are silently ignored.
      When set to C(warn), a warning message is displayed.
      The default option C(fail), triggers a failure and halts execution.
    vars:
    - name: ansible_network_become_errors
    default: fail
    choices: ["ignore", "warn", "fail"]
  terminal_errors:
    type: str
    description:
    - This option determines how failures while setting terminal parameters
      are handled.
    - When set to C(ignore), the errors are silently ignored.
      When set to C(warn), a warning message is displayed.
      The default option C(fail), triggers a failure and halts execution.
    vars:
    - name: ansible_network_terminal_errors
    default: fail
    choices: ["ignore", "warn", "fail"]
    version_added: 3.1.0
  become_method:
    description:
    - This option allows the become method to be specified in for handling privilege
      escalation.  Typically the become_method value is set to C(enable) but could
      be defined as other values.
    default: sudo
    type: string
    ini:
    - section: privilege_escalation
      key: become_method
    env:
    - name: ANSIBLE_BECOME_METHOD
    vars:
    - name: ansible_become_method
  host_key_auto_add:
    type: boolean
    description:
    - By default, Ansible will prompt the user before adding SSH keys to the known
      hosts file.  Since persistent connections such as network_cli run in background
      processes, the user will never be prompted.  By enabling this option, unknown
      host keys will automatically be added to the known hosts file.
    - Be sure to fully understand the security implications of enabling this option
      on production systems as it could create a security vulnerability.
    default: false
    ini:
    - section: paramiko_connection
      key: host_key_auto_add
    env:
    - name: ANSIBLE_HOST_KEY_AUTO_ADD
  persistent_buffer_read_timeout:
    type: float
    description:
    - Configures, in seconds, the amount of time to wait for the data to be read from
      Paramiko channel after the command prompt is matched. This timeout value ensures
      that command prompt matched is correct and there is no more data left to be
      received from remote host.
    default: 0.1
    ini:
    - section: persistent_connection
      key: buffer_read_timeout
    env:
    - name: ANSIBLE_PERSISTENT_BUFFER_READ_TIMEOUT
    vars:
    - name: ansible_buffer_read_timeout
  terminal_stdout_re:
    type: list
    elements: dict
    description:
    - A single regex pattern or a sequence of patterns along with optional flags to
      match the command prompt from the received response chunk. This option accepts
      C(pattern) and C(flags) keys. The value of C(pattern) is a python regex pattern
      to match the response and the value of C(flags) is the value accepted by I(flags)
      argument of I(re.compile) python method to control the way regex is matched
      with the response, for example I('re.I').
    vars:
    - name: ansible_terminal_stdout_re
  terminal_stderr_re:
    type: list
    elements: dict
    description:
    - This option provides the regex pattern and optional flags to match the error
      string from the received response chunk. This option accepts C(pattern) and
      C(flags) keys. The value of C(pattern) is a python regex pattern to match the
      response and the value of C(flags) is the value accepted by I(flags) argument
      of I(re.compile) python method to control the way regex is matched with the
      response, for example I('re.I').
    vars:
    - name: ansible_terminal_stderr_re
  terminal_initial_prompt:
    type: list
    elements: string
    description:
    - A single regex pattern or a sequence of patterns to evaluate the expected prompt
      at the time of initial login to the remote host.
    vars:
    - name: ansible_terminal_initial_prompt
  terminal_initial_answer:
    type: list
    elements: string
    description:
    - The answer to reply with if the C(terminal_initial_prompt) is matched. The value
      can be a single answer or a list of answers for multiple terminal_initial_prompt.
      In case the login menu has multiple prompts the sequence of the prompt and excepted
      answer should be in same order and the value of I(terminal_prompt_checkall)
      should be set to I(True) if all the values in C(terminal_initial_prompt) are
      expected to be matched and set to I(False) if any one login prompt is to be
      matched.
    vars:
    - name: ansible_terminal_initial_answer
  terminal_initial_prompt_checkall:
    type: boolean
    description:
    - By default the value is set to I(False) and any one of the prompts mentioned
      in C(terminal_initial_prompt) option is matched it won't check for other prompts.
      When set to I(True) it will check for all the prompts mentioned in C(terminal_initial_prompt)
      option in the given order and all the prompts should be received from remote
      host if not it will result in timeout.
    default: false
    vars:
    - name: ansible_terminal_initial_prompt_checkall
  terminal_inital_prompt_newline:
    type: boolean
    description:
    - This boolean flag, that when set to I(True) will send newline in the response
      if any of values in I(terminal_initial_prompt) is matched.
    default: true
    vars:
    - name: ansible_terminal_initial_prompt_newline
  network_cli_retries:
    description:
    - Number of attempts to connect to remote host. The delay time between the retires
      increases after every attempt by power of 2 in seconds till either the maximum
      attempts are exhausted or any of the C(persistent_command_timeout) or C(persistent_connect_timeout)
      timers are triggered.
    default: 3
    type: integer
    env:
    - name: ANSIBLE_NETWORK_CLI_RETRIES
    ini:
    - section: persistent_connection
      key: network_cli_retries
    vars:
    - name: ansible_network_cli_retries
  ssh_type:
    description:
      - The python package that will be used by the C(network_cli) connection plugin to create a SSH connection to remote host.
      - I(libssh) will use the ansible-pylibssh package, which needs to be installed in order to work.
      - I(paramiko) will instead use the paramiko package to manage the SSH connection.
      - I(auto) will use ansible-pylibssh if that package is installed, otherwise will fallback to paramiko.
    default: auto
    choices: ["kbd_interactive", "libssh", "paramiko", "auto"]
    type: string
    env:
        - name: ANSIBLE_NETWORK_CLI_SSH_TYPE
    ini:
        - section: persistent_connection
          key: ssh_type
    vars:
    - name: ansible_network_cli_ssh_type
  host_key_checking:
    description: 'Set this to "False" if you want to avoid host key checking by the underlying tools Ansible uses to connect to the host'
    type: boolean
    default: True
    env:
    - name: ANSIBLE_HOST_KEY_CHECKING
    - name: ANSIBLE_SSH_HOST_KEY_CHECKING
    ini:
    - section: defaults
      key: host_key_checking
    - section: persistent_connection
      key: host_key_checking
    vars:
    - name: ansible_host_key_checking
    - name: ansible_ssh_host_key_checking
  single_user_mode:
    type: boolean
    default: false
    version_added: 2.0.0
    description:
    - This option enables caching of data fetched from the target for re-use.
      The cache is invalidated when the target device enters configuration mode.
    - Applicable only for platforms where this has been implemented.
    env:
    - name: ANSIBLE_NETWORK_SINGLE_USER_MODE
    vars:
    - name: ansible_network_single_user_mode
"""

import getpass
import json
import logging
import os
import re
import signal
import socket
import time
import traceback

from functools import wraps
from io import BytesIO

from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.six import PY3
from ansible.module_utils.six.moves import cPickle
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import cache_loader, cliconf_loader, connection_loader, terminal_loader
from ansible.utils.display import Display

from ansible_collections.ansible.netcommon.plugins.connection.libssh import HAS_PYLIBSSH
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list
from ansible_collections.ansible.netcommon.plugins.plugin_utils.connection_base import (
    NetworkConnectionBase,
)


try:
    from scp import SCPClient

    HAS_SCP = True
except ImportError:
    HAS_SCP = False
display = Display()


def ensure_connect(func):
    @wraps(func)
    def wrapped(self, *args, **kwargs):
        if not self._connected:
            self._connect()
        self.update_cli_prompt_context()
        return func(self, *args, **kwargs)

    return wrapped


class AnsibleCmdRespRecv(Exception):
    pass


class Connection(NetworkConnectionBase):
    """CLI (shell) SSH connections on Paramiko"""

    transport = "evajust.kbd_interactive.network_cli"
    has_pipelining = True

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)
        self._ssh_shell = None

        self._matched_prompt = None
        self._matched_cmd_prompt = None
        self._matched_pattern = None
        self._last_response = None
        self._history = list()
        self._command_response = None
        self._last_recv_window = None
        self._cache = None

        self._terminal = None
        self.cliconf = None

        # Managing prompt context
        self._check_prompt = False

        self._task_uuid = to_text(kwargs.get("task_uuid", ""))
        self._ssh_type_conn = None
        self._ssh_type = None

        self._single_user_mode = False

        if self._network_os:
            self._terminal = terminal_loader.get(self._network_os, self)
            if not self._terminal:
                raise AnsibleConnectionFailure("network os %s is not supported" % self._network_os)

            self.cliconf = cliconf_loader.get(self._network_os, self)
            if not self.cliconf:
                self.queue_message(
                    "vvvv",
                    "unable to load cliconf for network_os %s. Falling back to default"
                    % self._network_os,
                )
                self.cliconf = cliconf_loader.get("ansible.netcommon.default", self)
                if not self.cliconf:
                    raise AnsibleConnectionFailure("Couldn't load fallback cliconf plugin")

            self._sub_plugin = {
                "type": "cliconf",
                "name": self.cliconf._load_name,
                "obj": self.cliconf,
            }
            self.queue_message(
                "vvvv",
                "loaded cliconf plugin %s from path %s for network_os %s"
                % (
                    self.cliconf._load_name,
                    self.cliconf._original_path,
                    self._network_os,
                ),
            )
        else:
            raise AnsibleConnectionFailure(
                "Unable to automatically determine host network os. Please "
                "manually configure ansible_network_os value for this host"
            )
        self.queue_message("log", "network_os is set to %s" % self._network_os)

    @property
    def ssh_type(self):
        if self._ssh_type is None:
            self._ssh_type = self.get_option("ssh_type")
            self.queue_message("vvvv", "ssh type is set to %s" % self._ssh_type)
            # Support autodetection of supported library
            if self._ssh_type == "auto":
                self.queue_message("vvvv", "autodetecting ssh_type")
                if HAS_PYLIBSSH:
                    self._ssh_type = "libssh"
                else:
                    self.queue_message(
                        "warning",
                        "ansible-pylibssh not installed, falling back to paramiko",
                    )
                    self._ssh_type = "paramiko"
                self.queue_message("vvvv", "ssh type is now set to %s" % self._ssh_type)

        if self._ssh_type not in ["paramiko", "libssh", "kbd_interactive"]:
            raise AnsibleConnectionFailure(
                "Invalid value '%s' set for ssh_type option."
                " Expected value is either 'libssh', 'paramiko', or 'kbd_interactive'" % self._ssh_type
            )

        return self._ssh_type

    @property
    def ssh_type_conn(self):
        if self._ssh_type_conn is None:
            if self.ssh_type == "libssh":
                connection_plugin = "ansible.netcommon.libssh"
            elif self.ssh_type == "paramiko":
                # NOTE: This MUST be paramiko or things will break
                connection_plugin = "paramiko"
            elif self.ssh_type == "kbd_interactive":
                connection_plugin = "evajust.kbd_interactive.kbd_interactive"
            else:
                raise AnsibleConnectionFailure(
                    "Invalid value '%s' set for ssh_type option."
                    " Expected value is either 'libssh' or 'paramiko'" % self._ssh_type
                )

            self._ssh_type_conn = connection_loader.get(
                connection_plugin, self._play_context, "/dev/null"
            )

        return self._ssh_type_conn

    # To maintain backward compatibility
    @property
    def paramiko_conn(self):
        return self.ssh_type_conn

    def _get_log_channel(self):
        user = ""
        try:
            user = getpass.getuser()
        except KeyError:
            self.queue_message(
                "vv",
                "Current user (uid=%s) does not seem to exist on this system, leaving user empty."
                % os.getuid(),
            )
        name = "p=%s u=%s | " % (os.getpid(), user)
        name += "%s [%s]" % (self.ssh_type, self._play_context.remote_addr)
        return name

    @ensure_connect
    def get_prompt(self):
        """Returns the current prompt from the device"""
        return self._matched_prompt

    def exec_command(self, cmd, in_data=None, sudoable=True):
        # not accessible code alert can be taken out at around  01-01-2027,
        # when connection local is removed
        if self._ssh_shell:
            try:
                cmd = json.loads(to_text(cmd, errors="surrogate_or_strict"))
                kwargs = {"command": to_bytes(cmd["command"], errors="surrogate_or_strict")}
                for key in (
                    "prompt",
                    "answer",
                    "sendonly",
                    "newline",
                    "prompt_retry_check",
                ):
                    if cmd.get(key) is True or cmd.get(key) is False:
                        kwargs[key] = cmd[key]
                    elif cmd.get(key) is not None:
                        kwargs[key] = to_bytes(cmd[key], errors="surrogate_or_strict")
                return self.send(**kwargs)
            except ValueError:
                cmd = to_bytes(cmd, errors="surrogate_or_strict")
                return self.send(command=cmd)

        else:
            return super(Connection, self).exec_command(cmd, in_data, sudoable)

    def get_options(self, hostvars=None):
        options = super(Connection, self).get_options(hostvars=hostvars)
        options.update(self.ssh_type_conn.get_options(hostvars=hostvars))
        return options

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super(Connection, self).set_options(
            task_keys=task_keys, var_options=var_options, direct=direct
        )
        self.ssh_type_conn.set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        # Retain old look_for_keys behaviour, but only if not set
        if not any(
            [
                task_keys and ("look_for_keys" in task_keys),
                var_options and ("look_for_keys" in var_options),
                direct and ("look_for_keys" in direct),
            ]
        ):
            look_for_keys = not bool(
                self.get_option("password") and not self.get_option("private_key_file")
            )
            if not look_for_keys:
                # This actually can't be overridden yet without changes in ansible-core
                # TODO: Uncomment when appropriate
                # self.queue_message(
                #     "warning",
                #     "Option look_for_keys has been implicitly set to {0} because "
                #     "it was not set explicitly. This is retained to maintain "
                #     "backwards compatibility with the old behavior. This behavior "
                #     "will be removed in some release after 2024-01-01".format(
                #         look_for_keys
                #     ),
                # )
                self.ssh_type_conn.set_option("look_for_keys", look_for_keys)

    def update_play_context(self, pc_data):
        """Updates the play context information for the connection"""
        pc_data = to_bytes(pc_data)
        if PY3:
            pc_data = cPickle.loads(pc_data, encoding="bytes")
        else:
            pc_data = cPickle.loads(pc_data)
        play_context = PlayContext()
        play_context.deserialize(pc_data)

        self.queue_message("vvvv", "updating play_context for connection")
        if self._play_context.become ^ play_context.become:
            if play_context.become is True:
                auth_pass = play_context.become_pass
                self._on_become(become_pass=auth_pass)
                self.queue_message("vvvv", "authorizing connection")
            else:
                self._terminal.on_unbecome()
                self.queue_message("vvvv", "deauthorizing connection")

        self._play_context = play_context
        if self._ssh_type_conn is not None:
            # TODO: This works, but is not really ideal. We would rather use
            #       set_options, but then we need more custom handling in that
            #       method.
            self._ssh_type_conn._play_context = play_context

        if hasattr(self, "reset_history"):
            self.reset_history()
        if hasattr(self, "disable_response_logging"):
            self.disable_response_logging()

        self._single_user_mode = self.get_option("single_user_mode")

    def set_check_prompt(self, task_uuid):
        self._check_prompt = task_uuid

    def update_cli_prompt_context(self):
        # set cli prompt context at the start of new task run only
        if self._check_prompt and self._task_uuid != self._check_prompt:
            self._task_uuid, self._check_prompt = self._check_prompt, False
            self.set_cli_prompt_context()

    def _connect(self):
        """
        Connects to the remote device and starts the terminal
        """
        if display.verbosity > 3:
            logging.getLogger(self.ssh_type).setLevel(logging.DEBUG)

        self.queue_message("vvvv", "invoked shell using ssh_type: %s" % self.ssh_type)

        self._single_user_mode = self.get_option("single_user_mode")

        if not self.connected:
            self.ssh_type_conn._set_log_channel(self._get_log_channel())
            self.ssh_type_conn.force_persistence = self.force_persistence

            command_timeout = self.get_option("persistent_command_timeout")
            max_pause = min(
                [
                    self.get_option("persistent_connect_timeout"),
                    command_timeout,
                ]
            )
            retries = self.get_option("network_cli_retries")
            total_pause = 0

            for attempt in range(retries + 1):
                try:
                    ssh = self.ssh_type_conn._connect()
                    break
                except AnsibleError:
                    raise
                except Exception as e:
                    pause = 2 ** (attempt + 1)
                    if attempt == retries or total_pause >= max_pause:
                        raise AnsibleConnectionFailure(to_text(e, errors="surrogate_or_strict"))
                    else:
                        msg = (
                            "network_cli_retry: attempt: %d, caught exception(%s), "
                            "pausing for %d seconds"
                            % (
                                attempt + 1,
                                to_text(e, errors="surrogate_or_strict"),
                                pause,
                            )
                        )

                        self.queue_message("vv", msg)
                        time.sleep(pause)
                        total_pause += pause
                        continue

            self.queue_message("vvvv", "ssh connection done, setting terminal")
            self._connected = True

            if self.ssh_type == "kbd_interactive":
                self._ssh_shell = ssh.ssh
                self._ssh_shell.invoke_shell()
            else:
                self._ssh_shell = ssh.ssh.invoke_shell()
                if self.ssh_type == "paramiko":
                    self._ssh_shell.settimeout(command_timeout)

            self.queue_message(
                "vvvv",
                "loaded terminal plugin for network_os %s" % self._network_os,
            )

            terminal_initial_prompt = (
                self.get_option("terminal_initial_prompt") or self._terminal.terminal_initial_prompt
            )
            terminal_initial_answer = (
                self.get_option("terminal_initial_answer") or self._terminal.terminal_initial_answer
            )
            newline = (
                self.get_option("terminal_inital_prompt_newline")
                or self._terminal.terminal_inital_prompt_newline
            )
            check_all = self.get_option("terminal_initial_prompt_checkall") or False

            self.receive(
                prompts=terminal_initial_prompt,
                answer=terminal_initial_answer,
                newline=newline,
                check_all=check_all,
            )

            if self._play_context.become:
                self.queue_message("vvvv", "firing event: on_become")
                auth_pass = self._play_context.become_pass
                self._on_become(become_pass=auth_pass)

            self.queue_message("vvvv", "firing event: on_open_shell()")
            self._on_open_shell()

            self.queue_message("vvvv", "ssh connection has completed successfully")

        return self

    def _on_become(self, become_pass=None):
        """
        Wraps terminal.on_become() to handle
        privilege escalation failures based on user preference
        """
        on_become_error = self.get_option("become_errors")
        try:
            self._terminal.on_become(passwd=become_pass)
        except AnsibleConnectionFailure:
            if on_become_error == "ignore":
                pass
            elif on_become_error == "warn":
                self.queue_message("warning", "on_become: privilege escalation failed")
            else:
                raise

    def _on_open_shell(self):
        """
        Wraps terminal.on_open_shell() to handle
        terminal setting failures based on user preference
        """
        on_terminal_error = self.get_option("terminal_errors")
        try:
            self._terminal.on_open_shell()
        except AnsibleConnectionFailure:
            if on_terminal_error == "ignore":
                pass
            elif on_terminal_error == "warn":
                self.queue_message(
                    "warning",
                    "on_open_shell: failed to set terminal parameters",
                )
            else:
                raise

    def close(self):
        """
        Close the active connection to the device
        """
        # only close the connection if its connected.
        if self._connected:
            self.queue_message("debug", "closing ssh connection to device")
            if self._ssh_shell:
                self.queue_message("debug", "firing event: on_close_shell()")
                self._terminal.on_close_shell()
                self._ssh_shell.close()
                self._ssh_shell = None
                self.queue_message("debug", "cli session is now closed")

                self.ssh_type_conn.close()
                self._ssh_type_conn = None
                self.queue_message("debug", "ssh connection has been closed successfully")
        super(Connection, self).close()

    def _read_post_command_prompt_match(self):
        time.sleep(self.get_option("persistent_buffer_read_timeout"))
        data = self._ssh_shell.read_bulk_response()
        return data if data else None

    def receive_paramiko(
        self,
        command=None,
        prompts=None,
        answer=None,
        newline=True,
        prompt_retry_check=False,
        check_all=False,
        strip_prompt=True,
    ):
        recv = BytesIO()
        cache_socket_timeout = self.get_option("persistent_command_timeout")
        self._ssh_shell.settimeout(cache_socket_timeout)
        command_prompt_matched = False
        handled = False
        errored_response = None

        while True:
            if command_prompt_matched:
                try:
                    signal.signal(signal.SIGALRM, self._handle_buffer_read_timeout)
                    signal.setitimer(signal.ITIMER_REAL, self._buffer_read_timeout)
                    data = self._ssh_shell.recv(256)
                    signal.alarm(0)
                    self._log_messages("response-%s: %s" % (self._window_count + 1, data))
                    # if data is still received on channel it indicates the prompt string
                    # is wrongly matched in between response chunks, continue to read
                    # remaining response.
                    command_prompt_matched = False

                    # restart command_timeout timer
                    signal.signal(signal.SIGALRM, self._handle_command_timeout)
                    signal.alarm(self._command_timeout)

                except AnsibleCmdRespRecv:
                    # reset socket timeout to global timeout
                    return self._command_response
            else:
                data = self._ssh_shell.recv(256)
                self._log_messages("response-%s: %s" % (self._window_count + 1, data))
            # when a channel stream is closed, received data will be empty
            if not data:
                break

            recv.write(data)
            offset = recv.tell() - 256 if recv.tell() > 256 else 0
            recv.seek(offset)

            window = self._strip(recv.read())
            self._last_recv_window = window
            self._window_count += 1

            if prompts and not handled:
                handled = self._handle_prompt(window, prompts, answer, newline, False, check_all)
                self._matched_prompt_window = self._window_count
            elif (
                prompts
                and handled
                and prompt_retry_check
                and self._matched_prompt_window + 1 == self._window_count
            ):
                # check again even when handled, if same prompt repeats in next window
                # (like in the case of a wrong enable password, etc) indicates
                # value of answer is wrong, report this as error.
                if self._handle_prompt(
                    window,
                    prompts,
                    answer,
                    newline,
                    prompt_retry_check,
                    check_all,
                ):
                    raise AnsibleConnectionFailure(
                        "For matched prompt '%s', answer is not valid" % self._matched_cmd_prompt
                    )

            if self._find_error(window):
                # We can't exit here, as we need to drain the buffer in case
                # the error isn't fatal, and will be using the buffer again
                errored_response = window

            if self._find_prompt(window):
                if errored_response:
                    raise AnsibleConnectionFailure(errored_response)
                self._last_response = recv.getvalue()
                resp = self._strip(self._last_response)
                self._command_response = self._sanitize(resp, command, strip_prompt)
                if self._buffer_read_timeout == 0.0:
                    # reset socket timeout to global timeout
                    return self._command_response
                else:
                    command_prompt_matched = True

    def receive_libssh(
        self,
        command=None,
        prompts=None,
        answer=None,
        newline=True,
        prompt_retry_check=False,
        check_all=False,
        strip_prompt=True,
    ):
        self._command_response = resp = b""
        command_prompt_matched = False
        handled = False
        errored_response = None

        while True:
            if command_prompt_matched:
                data = self._read_post_command_prompt_match()
                if data:
                    command_prompt_matched = False
                else:
                    return self._command_response
            else:
                try:
                    data = self._ssh_shell.read_bulk_response()
                # TODO: Should be ConnectionError when pylibssh drops Python 2 support
                except OSError:
                    # Socket has closed
                    break

            if not data:
                continue
            self._last_recv_window = self._strip(data)
            resp += self._last_recv_window
            self._window_count += 1

            self._log_messages("response-%s: %s" % (self._window_count, data))

            if prompts and not handled:
                handled = self._handle_prompt(resp, prompts, answer, newline, False, check_all)
                self._matched_prompt_window = self._window_count
            elif (
                prompts
                and handled
                and prompt_retry_check
                and self._matched_prompt_window + 1 == self._window_count
            ):
                # check again even when handled, if same prompt repeats in next window
                # (like in the case of a wrong enable password, etc) indicates
                # value of answer is wrong, report this as error.
                if self._handle_prompt(
                    resp,
                    prompts,
                    answer,
                    newline,
                    prompt_retry_check,
                    check_all,
                ):
                    raise AnsibleConnectionFailure(
                        "For matched prompt '%s', answer is not valid" % self._matched_cmd_prompt
                    )

            if self._find_error(resp):
                # We can't exit here, as we need to drain the buffer in case
                # the error isn't fatal, and will be using the buffer again
                errored_response = resp

            if self._find_prompt(resp):
                if errored_response:
                    raise AnsibleConnectionFailure(errored_response)
                self._last_response = data
                self._command_response = self._sanitize(resp, command, strip_prompt)
                command_prompt_matched = True

    def receive(
        self,
        command=None,
        prompts=None,
        answer=None,
        newline=True,
        prompt_retry_check=False,
        check_all=False,
        strip_prompt=True,
    ):
        """
        Handles receiving of output from command
        """
        self._matched_prompt = None
        self._matched_cmd_prompt = None
        self._matched_prompt_window = 0
        self._window_count = 0

        # set terminal regex values for command prompt and errors in response
        self._terminal_stderr_re = self._get_terminal_std_re("terminal_stderr_re")
        self._terminal_stdout_re = self._get_terminal_std_re("terminal_stdout_re")

        self._command_timeout = self.get_option("persistent_command_timeout")
        self._validate_timeout_value(self._command_timeout, "persistent_command_timeout")

        self._buffer_read_timeout = self.get_option("persistent_buffer_read_timeout")
        self._validate_timeout_value(self._buffer_read_timeout, "persistent_buffer_read_timeout")

        self._log_messages("command: %s" % command)
        if self.ssh_type == "libssh":
            response = self.receive_libssh(
                command,
                prompts,
                answer,
                newline,
                prompt_retry_check,
                check_all,
                strip_prompt,
            )
        elif (
            self.ssh_type == "paramiko" or
            self.ssh_type == "kbd_interactive"
        ):
            response = self.receive_paramiko(
                command,
                prompts,
                answer,
                newline,
                prompt_retry_check,
                check_all,
                strip_prompt,
            )

        return response

    @ensure_connect
    def send(
        self,
        command,
        prompt=None,
        answer=None,
        newline=True,
        sendonly=False,
        prompt_retry_check=False,
        check_all=False,
        strip_prompt=True,
    ):
        """
        Sends the command to the device in the opened shell
        """
        # try cache first
        if (not prompt) and (self._single_user_mode):
            out = self.get_cache().lookup(command)
            if out:
                self.queue_message("vvvv", "cache hit for command: %s" % command)
                return out

        if check_all:
            prompt_len = len(to_list(prompt))
            answer_len = len(to_list(answer))
            if prompt_len != answer_len:
                raise AnsibleConnectionFailure(
                    "Number of prompts (%s) is not same as that of answers (%s)"
                    % (prompt_len, answer_len)
                )
        try:
            cmd = b"%s\r" % command
            self._history.append(cmd)
            self._ssh_shell.sendall(cmd)
            self._log_messages("send command: %s" % cmd)
            if sendonly:
                return
            response = self.receive(
                command,
                prompt,
                answer,
                newline,
                prompt_retry_check,
                check_all,
                strip_prompt,
            )
            response = to_text(response, errors="surrogate_then_replace")

            if (not prompt) and (self._single_user_mode):
                if self._needs_cache_invalidation(command):
                    # invalidate the existing cache
                    if self.get_cache().keys():
                        self.queue_message("vvvv", "invalidating existing cache")
                        self.get_cache().invalidate()
                else:
                    # populate cache
                    self.queue_message("vvvv", "populating cache for command: %s" % command)
                    self.get_cache().populate(command, response)

            return response
        except (socket.timeout, AttributeError):
            self.queue_message("error", traceback.format_exc())
            raise AnsibleConnectionFailure(
                "timeout value %s seconds reached while trying to send command: %s"
                % (self._ssh_shell.gettimeout(), command.strip())
            )

    def _handle_buffer_read_timeout(self, signum, frame):
        self.queue_message(
            "vvvv",
            "Response received, triggered 'persistent_buffer_read_timeout' timer of %s seconds"
            % self.get_option("persistent_buffer_read_timeout"),
        )
        raise AnsibleCmdRespRecv()

    def _handle_command_timeout(self, signum, frame):
        msg = (
            "command timeout triggered, timeout value is %s secs.\nSee the timeout setting options in the Network Debug and Troubleshooting Guide."
            % self.get_option("persistent_command_timeout")
        )
        self.queue_message("log", msg)
        raise AnsibleConnectionFailure(msg)

    def _strip(self, data):
        """
        Removes ANSI codes from device response
        """
        for regex in self._terminal.ansi_re:
            data = regex.sub(b"", data)
        return data

    def _handle_prompt(
        self,
        resp,
        prompts,
        answer,
        newline,
        prompt_retry_check=False,
        check_all=False,
    ):
        """
        Matches the command prompt and responds

        :arg resp: Byte string containing the raw response from the remote
        :arg prompts: Sequence of byte strings that we consider prompts for input
        :arg answer: Sequence of Byte string to send back to the remote if we find a prompt.
                A carriage return is automatically appended to this string.
        :param prompt_retry_check: Bool value for trying to detect more prompts
        :param check_all: Bool value to indicate if all the values in prompt sequence should be matched or any one of
                          given prompt.
        :returns: True if a prompt was found in ``resp``. If check_all is True
                  will True only after all the prompt in the prompts list are matched. False otherwise.
        """
        single_prompt = False
        if not isinstance(prompts, list):
            prompts = [prompts]
            single_prompt = True
        if not isinstance(answer, list):
            answer = [answer]
        try:
            prompts_regex = [re.compile(to_bytes(r), re.I) for r in prompts]
        except re.error as exc:
            raise ConnectionError(
                "Failed to compile one or more terminal prompt regexes: %s.\n"
                "Prompts provided: %s" % (to_text(exc), prompts)
            )
        for index, regex in enumerate(prompts_regex):
            match = regex.search(resp)
            if match:
                self._matched_cmd_prompt = match.group()
                self._log_messages("matched command prompt: %s" % self._matched_cmd_prompt)

                # if prompt_retry_check is enabled to check if same prompt is
                # repeated don't send answer again.
                if not prompt_retry_check:
                    prompt_answer = to_bytes(answer[index] if len(answer) > index else answer[0])
                    if newline:
                        prompt_answer += b"\r"
                    self._ssh_shell.sendall(prompt_answer)
                    self._log_messages("matched command prompt answer: %s" % prompt_answer)
                if check_all and prompts and not single_prompt:
                    prompts.pop(0)
                    answer.pop(0)
                    return False
                return True
        return False

    def _sanitize(self, resp, command=None, strip_prompt=True):
        """
        Removes elements from the response before returning to the caller
        """
        cleaned = []
        for line in resp.splitlines():
            if command and line.strip() == command.strip():
                continue

            for prompt in self._matched_prompt.strip().splitlines():
                if prompt.strip() in line and strip_prompt:
                    break
            else:
                cleaned.append(line)

        return b"\n".join(cleaned).strip()

    def _find_error(self, response):
        """Searches the buffered response for a matching error condition"""
        for stderr_regex in self._terminal_stderr_re:
            if stderr_regex.search(response):
                self._log_messages(
                    "matched error regex (terminal_stderr_re) '%s' from response '%s'"
                    % (stderr_regex.pattern, response)
                )

                self._log_messages(
                    "matched stdout regex (terminal_stdout_re) '%s' from error response '%s'"
                    % (self._matched_pattern, response)
                )
                return True

        return False

    def _find_prompt(self, response):
        """Searches the buffered response for a matching command prompt"""
        for stdout_regex in self._terminal_stdout_re:
            match = stdout_regex.search(response)
            if match:
                self._matched_pattern = stdout_regex.pattern
                self._matched_prompt = match.group()
                self._log_messages(
                    "matched cli prompt '%s' with regex '%s' from response '%s'"
                    % (self._matched_prompt, self._matched_pattern, response)
                )
                return True

        return False

    def _validate_timeout_value(self, timeout, timer_name):
        if timeout < 0:
            raise AnsibleConnectionFailure(
                "'%s' timer value '%s' is invalid, value should be greater than or equal to zero."
                % (timer_name, timeout)
            )

    def transport_test(self, connect_timeout):
        """This method enables wait_for_connection to work.

        As it is used by wait_for_connection, it is called by that module's action plugin,
        which is on the controller process, which means that nothing done on this instance
        should impact the actual persistent connection... this check is for informational
        purposes only and should be properly cleaned up.
        """

        # Force a fresh connect if for some reason we have connected before.
        self.close()
        self._connect()
        self.close()

    def _get_terminal_std_re(self, option):
        terminal_std_option = self.get_option(option)
        terminal_std_re = []

        if terminal_std_option:
            for item in terminal_std_option:
                if "pattern" not in item:
                    raise AnsibleConnectionFailure(
                        "'pattern' is a required key for option '%s',"
                        " received option value is %s" % (option, item)
                    )
                pattern = rb"%s" % to_bytes(item["pattern"])
                flag = item.get("flags", 0)
                if flag:
                    flag = getattr(re, flag.split(".")[1])
                terminal_std_re.append(re.compile(pattern, flag))
        else:
            # To maintain backward compatibility
            terminal_std_re = getattr(self._terminal, option)

        return terminal_std_re

    def copy_file(self, source=None, destination=None, proto="scp", timeout=30):
        """Copies file over scp/sftp to remote device

        :param source: Source file path
        :param destination: Destination file path on remote device
        :param proto: Protocol to be used for file transfer,
                      supported protocol: scp and sftp
        :param timeout: Specifies the wait time to receive response from
                        remote host before triggering timeout exception
        :return: None
        """
        ssh = self.ssh_type_conn._connect_uncached()
        if self.ssh_type == "libssh":
            self.ssh_type_conn.put_file(source, destination, proto=proto)
        elif self.ssh_type == "paramiko":
            if proto == "scp":
                if not HAS_SCP:
                    raise AnsibleError(missing_required_lib("scp"))
                with SCPClient(ssh.get_transport(), socket_timeout=timeout) as scp:
                    scp.put(source, destination)
            elif proto == "sftp":
                with ssh.open_sftp() as sftp:
                    sftp.put(source, destination)
            else:
                raise AnsibleError("Do not know how to do transfer file over protocol %s" % proto)
        else:
            raise AnsibleError("Do not know how to do SCP with ssh_type %s" % self.ssh_type)

    def get_file(self, source=None, destination=None, proto="scp", timeout=30):
        """Fetch file over scp/sftp from remote device
        :param source: Source file path
        :param destination: Destination file path
        :param proto: Protocol to be used for file transfer,
                      supported protocol: scp and sftp
        :param timeout: Specifies the wait time to receive response from
                        remote host before triggering timeout exception
        :return: None
        """
        """Fetch file over scp/sftp from remote device"""
        ssh = self.ssh_type_conn._connect_uncached()
        if self.ssh_type == "libssh":
            self.ssh_type_conn.fetch_file(source, destination, proto=proto)
        elif self.ssh_type == "paramiko":
            if proto == "scp":
                if not HAS_SCP:
                    raise AnsibleError(missing_required_lib("scp"))
                try:
                    with SCPClient(ssh.get_transport(), socket_timeout=timeout) as scp:
                        scp.get(source, destination)
                except EOFError:
                    # This appears to be benign.
                    pass
            elif proto == "sftp":
                with ssh.open_sftp() as sftp:
                    sftp.get(source, destination)
            else:
                raise AnsibleError("Do not know how to do transfer file over protocol %s" % proto)
        else:
            raise AnsibleError("Do not know how to do SCP with ssh_type %s" % self.ssh_type)

    def get_cache(self):
        if not self._cache:
            # TO-DO: support jsonfile or other modes of caching with
            #        a configurable option
            self._cache = cache_loader.get("ansible.netcommon.memory")
        return self._cache

    def _is_in_config_mode(self):
        """
        Check if the target device is in config mode by comparing
        the current prompt with the platform's `terminal_config_prompt`.
        Returns False if `terminal_config_prompt` is not defined.

        :returns: A boolean indicating if the device is in config mode or not.
        """
        cfg_mode = False
        cur_prompt = to_text(self.get_prompt(), errors="surrogate_then_replace").strip()
        cfg_prompt = getattr(self._terminal, "terminal_config_prompt", None)
        if cfg_prompt and cfg_prompt.match(cur_prompt):
            cfg_mode = True
        return cfg_mode

    def _needs_cache_invalidation(self, command):
        """
        This method determines if it is necessary to invalidate
        the existing cache based on whether the device has entered
        configuration mode or if the last command sent to the device
        is potentially capable of making configuration changes.

        :param command: The last command sent to the target device.
        :returns: A boolean indicating if cache invalidation is required or not.
        """
        invalidate = False
        cfg_cmds = []
        try:
            # AnsiblePlugin base class in Ansible 2.9 does not have has_option() method.
            # TO-DO: use has_option() when we drop 2.9 support.
            cfg_cmds = self.cliconf.get_option("config_commands")
        except AttributeError:
            cfg_cmds = []
        if (self._is_in_config_mode()) or (to_text(command) in cfg_cmds):
            invalidate = True
        return invalidate
