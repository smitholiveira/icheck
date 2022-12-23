import yaml
from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
from os import rename
from os.path import isfile
from socket import getfqdn
from pysnmp.hlapi import *
from ipaddress import ip_network
from itertools import chain
import re

exceptions = (
    NetMikoAuthenticationException,
    NetMikoTimeoutException,
    Exception)


def netgen(network: list, what=''):
    try:
        network_gen = [ip_network(net).hosts() for net in network]
        network_merge = [net for net in chain.from_iterable(network_gen)]
        network_collection = [getfqdn(str(net)) for net in network_merge]

        if what == '':
            pattern = re.compile(r'\D')
            matches = list(set(filter(pattern.match, network_collection)))
            matches = sorted(matches)

        else:
            pattern = re.compile(f'^{what}')
            matches = list(set(filter(pattern.match, network_collection)))
            matches = sorted(matches)

        return matches

    except exceptions as error:
        print(error)
        exit()


class NetGen:
    def __init__(self, var_network: list):
        self.var_network = var_network

    def gen(self, var_what=''):
        return netgen(self.var_network, var_what)


def check_snmpv3(host):
    auth_priv = func_yml('pass_ucl.yml', 'snmpv3')
    user = auth_priv.get('user')
    sha = auth_priv.get('sha')
    aes = auth_priv.get('aes')

    snmpv3 = getCmd(SnmpEngine(),
                    UsmUserData(user, sha, aes,
                                authProtocol=usmHMACSHAAuthProtocol,
                                privProtocol=usmAesCfb128Protocol),
                    UdpTransportTarget((host, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
                    )

    error_indication, error_status, error_index, var_binds = next(snmpv3)

    if error_indication:
        return f'{"snmpv3 -> nope"}'
    elif error_status:
        return f'{"snmpv3 -> nope"}'
    elif error_index:
        return f'{"snmpv -> nope"}'
    else:
        return f'{"snmpv3 -> yeah"}'


def check_snmpv2_one_community(host):
    community = func_yml('pass_ucl.yml', 'snmpv2')
    community = community.get('community')

    snmpv2 = getCmd(SnmpEngine(),
                    CommunityData(community, mpModel=1),
                    UdpTransportTarget((host, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
                    # ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
                    )

    error_indication, error_status, error_index, var_binds = next(snmpv2)

    if error_indication:
        return f'{"snmpv2 -> nope"}'
    elif error_status:
        return f'{"snmpv2 -> nope"}'
    elif error_index:
        return f'{"snmpv2 -> nope"}'
    else:
        return f'{"snmpv2 -> yeah"}'


def check_snmpv2_list_community(host):
    community_list = func_yml('pass.yml', 'community')

    for cl in community_list:

        snmpv2 = getCmd(SnmpEngine(),
                        CommunityData(cl, mpModel=1),
                        UdpTransportTarget((host, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
                        # ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
                        )

        error_indication, error_status, error_index, var_binds = next(snmpv2)

        if error_indication:
            return f'{"snmpv2 -> nope"}'
        elif error_status:
            return f'{"snmpv2 -> nope"}'
        elif error_index:
            return f'{"snmpv2 -> nope"}'
        else:
            return f'{"snmpv2 -> yeah"}'


def shuffle(file_name, ext1, ext2):
    ext1 = f'-{ext1}'
    ext2 = f'.{ext2}'

    if isfile(f'{file_name}{ext1}'):
        if isfile(f'{file_name}{ext1}{ext2}''1'):
            if isfile(f'{file_name}{ext1}{ext2}''2'):
                if isfile(f'{file_name}{ext1}{ext2}''3'):
                    if isfile(f'{file_name}{ext1}{ext2}''4'):
                        if isfile(f'{file_name}{ext1}{ext2}''5'):
                            rename(f'{file_name}{ext1}{ext2}''2', f'{file_name}{ext1}{ext2}''1')
                            rename(f'{file_name}{ext1}{ext2}''3', f'{file_name}{ext1}{ext2}''2')
                            rename(f'{file_name}{ext1}{ext2}''4', f'{file_name}{ext1}{ext2}''3')
                            rename(f'{file_name}{ext1}{ext2}''5', f'{file_name}{ext1}{ext2}''4')
                            rename(f'{file_name}{ext1}', f'{file_name}{ext1}{ext2}''5')
                        else:
                            rename(f'{file_name}{ext1}', f'{file_name}{ext1}{ext2}''5')
                    else:
                        rename(f'{file_name}{ext1}', f'{file_name}{ext1}{ext2}''4')
                else:
                    rename(f'{file_name}{ext1}', f'{file_name}{ext1}{ext2}''3')
            else:
                rename(f'{file_name}{ext1}', f'{file_name}{ext1}{ext2}''2')
        else:
            rename(f'{file_name}{ext1}', f'{file_name}{ext1}{ext2}''1')
    open(f'{file_name}{ext1}', 'w')


def func_yml(file_path_yaml, group):
    """ Read key/value and list from a yaml file. """
    with open(file_path_yaml) as f:
        file_yaml = f.read()
    yaml_dict = yaml.load(file_yaml, Loader=yaml.FullLoader)
    return yaml_dict[group]


class Login:
    def __init__(self, var_credentials: dict, var_hosts, var_device_type):
        # self.var_credentials = var_credentials
        # self.var_hosts = var_hosts
        # self.var_device_type = var_device_type

        # remove the duplication and get fqdn
        remove_duplicate_hosts = [getfqdn(x) for x in set(var_hosts)]
        remove_duplicate_hosts = set(remove_duplicate_hosts)

        self.output = []

        for hosts in remove_duplicate_hosts:
            device = {
                'device_type': var_device_type,
                'host': hosts,
                # 'global_delay_factor': 2,
                # "read_timeout_override": 90,
                # 'banner_timeout': 20,
                'session_log': 'output_high-level.log'
            }

            try:
                device.update(var_credentials)
                net_connect = ConnectHandler(**device)
                net_connect.enable()
                self.output.append(net_connect)

            except exceptions as error:
                print(error)

    def login(self):
        return self.output


class Device(Login):
    def __init__(self, var_credentials, var_hosts, var_device_type):
        super().__init__(var_credentials, var_hosts, var_device_type)

    def prompt(self):
        net_connect = self.login()

        output = []
        for net in net_connect:
            try:
                display = net.find_prompt()
                output.append(display)
            except exceptions as error:
                print(error)

        return output

    def show(self, var_command):
        net_connect = self.login()

        output = []
        for net in net_connect:
            for command in var_command:
                try:
                    display = net.send_command(command, max_loops=1000, delay_factor=5)
                    output.append(display)
                except exceptions as error:
                    print(error)

        return output

    def config(self, var_command):
        net_connect = self.login()

        output = []
        for net in net_connect:
            try:
                display = net.send_config_set(var_command, max_loops=1000, delay_factor=5)
                output.append(display)
            except exceptions as error:
                print(error)

        return output

    def save(self):
        net_connect = self.login()

        output = []
        for net in net_connect:
            try:
                display = net.save_config()
                output.append(display)
            except exceptions as error:
                print(error)

        return output

    def backup(self, folder):
        net_connect = self.login()

        var_command = 'sh run'

        output = []
        for net in net_connect:
            try:
                display = net.send_command(var_command, max_loops=1000, delay_factor=5)
                output.append(display)

                folder_file_name = f'{folder}/{net.host}'

                # shuffle
                shuffle(folder_file_name, 'confg', 'BAK')

                # copy the 'sh ver' output to a file
                for o in output:
                    with open(f'{folder_file_name}-confg', 'w') as f:
                        f.write(o)

            except exceptions as error:
                print(error)

        return output


if __name__ == '__main__':
    # cred_iosxe = func_yml('pass.yml', 'cred_iosxe')
    # host_iosxe = func_yml('pass.yml', 'host_iosxe')

    # cred_nxos = func_yml('pass.yml', 'cred_nxos')
    # host_nxos = func_yml('pass.yml', 'host_nxos')
    #
    # iosxe = Device(cred_iosxe, host_iosxe, 'cisco_ios')
    # print(iosxe.prompt())
    # print(iosxe.show(['sh clock', 'sh snmp location']))
    # print(iosxe.config(['ip host dns.google 8.8.8.8', 'ip host dns9.quad9.net 9.9.9.9']))
    # print(iosxe.save())
    # print(iosxe.backup('tftp'))
    #
    # cred_oliveiras = func_yml('pass.yml', 'cred_oliveiras')
    # host_oliveiras = func_yml('pass.yml', 'host_oliveiras')
    #
    # oliveiras = Device(cred_oliveiras, host_oliveiras, 'cisco_ios')
    # print(oliveiras.prompt())
    # print(oliveiras.show(['sh clock', 'sh snmp location']))
    # print(oliveiras.config(['ip host dns.google 8.8.8.8']))
    # print(oliveiras.save())
    # print(oliveiras.backup('tftp'))

    ios = NetGen(['128.40.0.0/24'])
    for n in ios.gen():
        print(f'\t- {n}')
