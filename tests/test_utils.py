"""
    pyznap.tests.test_utils
    ~~~~~~~~~~~~~~

    Helper functions for tests.

    :copyright: (c) 2018-2019 by Yannick Boetzel.
    :license: GPLv3, see LICENSE for more details.
"""


import os
import logging

import paramiko as pm
from socket import timeout, gaierror
from paramiko.ssh_exception import (AuthenticationException, BadAuthenticationType,
                                    BadHostKeyException, ChannelException, NoValidConnectionsError,
                                    PasswordRequiredException, SSHException, PartialAuthentication,
                                    ProxyCommandFailure)


def open_ssh(user, host, key=None, port=22):
    """Opens an ssh connection to host.

    Parameters:
    ----------
    user : {str}
        Username to use
    host : {str}
        Host to connect to
    key : {str}, optional
        Path to ssh keyfile (the default is None, meaning the standard locations
        '~/.ssh/id_rsa' or '~/.ssh/id_ed25519' will be checked)
    port : {int}, optional
        Port number to connect to (the default is 22)

    Raises
    ------
    FileNotFoundError
        If keyfile does not exist
    SSHException
        General exception raised if anything goes wrong during ssh connection

    Returns
    -------
    paramiko.SSHClient
        Open ssh connection.
    """

    logger = logging.getLogger(__name__)

    if key:
        if not os.path.isfile(key):
            logger.error('{} is not a valid ssh key file...'.format(key))
            raise FileNotFoundError(key)
    else:
        # Try id_rsa first, then id_ed25519
        id_rsa = os.path.expanduser('~/.ssh/id_rsa')
        id_ed25519 = os.path.expanduser('~/.ssh/id_ed25519')
        
        if os.path.isfile(id_rsa):
            key = id_rsa
        elif os.path.isfile(id_ed25519):
            key = id_ed25519
        else:
            logger.error('No valid ssh key found at {} or {}...'.format(id_rsa, id_ed25519))
            raise FileNotFoundError('No valid ssh key found at {} or {}'.format(id_rsa, id_ed25519))

    ssh = pm.SSHClient()
    # Append username & hostname attributes to ssh class
    ssh.user, ssh.host = user, host
    try:
        ssh.load_system_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    except (IOError, FileNotFoundError):
        ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(pm.WarningPolicy())

    try:
        ssh.connect(hostname=host, port=port, username=user, key_filename=key, timeout=5,
                    look_for_keys=False)
        # Test connection
        ssh.exec_command('ls', timeout=5)
    except (AuthenticationException, BadAuthenticationType,
            BadHostKeyException, ChannelException, NoValidConnectionsError,
            PasswordRequiredException, SSHException, PartialAuthentication,
            ProxyCommandFailure, timeout, gaierror) as err:
        logger.error('Could not connect to host {:s}: {}...'.format(host, err))
        # Raise general exception to be catched outside
        raise SSHException(err)

    return ssh