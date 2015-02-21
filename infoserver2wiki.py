#!/usr/bin/env python
#-*- coding: utf-8 -*-

''' infoserver2wiki - List some operating system information and creates a text file in the format dokuwiki'''

import sys
import os
import re
import socket
import psutil
import struct
import platform

osdistro = platform.dist()
distro = osdistro[0].lower()

hostname = socket.gethostname()

reporttxt = ('/tmp/%s.txt' % hostname)

def convert_bytes(bytes):
    '''Convert from bytes to megabyte '''

    bytes = float(bytes)
    if bytes >= 1099511627776:
        terabytes = bytes / 1099511627776
        size = '%.2fT' % terabytes
    elif bytes >= 1073741824:
        gigabytes = bytes / 1073741824
        size = '%.2fG' % gigabytes
    elif bytes >= 1048576:
        megabytes = bytes / 1048576
        size = '%.2fM' % megabytes
    elif bytes >= 1024:
        kilobytes = bytes / 1024
        size = '%.2fK' % kilobytes
    else:
        size = '%.2fb' % bytes
    return size


def putline(line):
    ''' Function that enhances the print() and print the text file '''
    print line
    filereport = open(reporttxt, 'a')
    line = re.sub(r'(?is)\033\[.*?m', '', line)
    filereport.write(line.replace(line, line + '\n'))


def header():
    ''' Documentation header'''

    fqdn = socket.getfqdn()
    arch = platform.machine()

    putline('======' + hostname + '======')
    putline('FQDN: ' + fqdn)
    putline(' ')
    putline('Operation System: ' + osdistro[0] + " " + arch)
    putline('----------------------------------------------')


def show_cpu():
    '''Show CPUS'''
    number_cpus = psutil.cpu_count()
    putline('')
    putline('\033[93m' + '=== CPU ===')
    putline('\033[0m' + 'Total cpus: ' + str(number_cpus))


def show_memory():
    '''Displays amount of memory'''
    putline('')
    putline('\033[93m' + '=== Memory ===')
    uso_memory = psutil.virtual_memory()
    total_swap = psutil.swap_memory()
    putline('\033[0m' + 'Memory: ' +
            str(convert_bytes(uso_memory[0])))
    putline(' ')
    putline('\033[0m' + 'swap: ' + str(convert_bytes(total_swap[0])))


def show_partitions():
    ''' Show partitions '''
    partitions = psutil.disk_partitions()
    putline('')
    putline('\033[93m' + '=== Mount Points ===')

    putline('\033[0m' + "^Device ^ Mount Point ^FileSystem ^ Options ^ ")
    for item in partitions:
        putline('\033[0m' + '|' + str(item[0]) + '|' + str(
            item[1]) + '|' + str(item[2]) + '|' + str(item[3]) + '|')


def list_interfaces():
    '''list network interfaces'''

    putline('')
    putline('\033[93m' + '=== Interfaces ===')

    def all_interfaces():
        '''get all interfaces'''
        import array
        import fcntl

        max_possible = 128  # arbitrary. raise if needed.
        bytes = max_possible * 32
        allinterface = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            allinterface.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes, names.buffer_info()[0])
        ))[0]
        namestr = names.tostring()
        lst = []
        for i in range(0, outbytes, 40):
            name = namestr[i:i + 16].split('\0', 1)[0]
            ipaddr = namestr[i + 20:i + 24]
            lst.append((name, ipaddr))
        return lst

    def format_ip(addr):
        '''format ip address'''
        return str(ord(addr[0])) + '.' + \
            str(ord(addr[1])) + '.' + \
            str(ord(addr[2])) + '.' + \
            str(ord(addr[3]))

    ifs = all_interfaces()
    putline('\033[0m' + "^Interface ^ Address ^")
    for i in ifs:
        putline('\033[0m' + "|%1s|%s|" % (i[0], format_ip(i[1])))


def show_chkconfig():
    '''Displays the services enabled at startup'''
    putline('')
    putline('\033[93m' + '=== Services enabled at startup ===')

    if 'centos' in distro:
        servicescentos = []
        chkconfigon = os.popen('chkconfig |grep 3:on |awk \'{print $1}\'')
        for line in chkconfigon:
            servicescentos.append(line.strip())
        putline('\033[94m' + str(servicescentos))

    elif "ubuntu" == distro:
        serviceschk = []
        services_running_ubuntu = os.popen('/sbin/initctl list |grep running')
        for line in services_running_ubuntu:
            serviceschk.append(line.replace('start/running,', '').strip())

        for servicosrodando in serviceschk:
            #ServicosRodando.replace('start/running,', '')
            putline('\033[92m' + '' + '  *  ' + servicosrodando)
    elif "gentoo" == distro:
        servicesgentoo = []
        services_running_gentoo = os.popen("rc-status |grep started |awk {'print $1'}")

        for line in services_running_gentoo:
            servicesgentoo.append(line.strip())

        for servicesenabledgentoo in servicesgentoo:
            putline('\033[94m' + " * "+ str(servicesenabledgentoo))

    else:
        putline('\033[94m' + " * distro unknown ")

def check_iptables():
    '''List the rules of iptables'''
    import iptc
    table = iptc.Table(iptc.Table.FILTER)

    putline('')
    putline('\033[93m' + '=== Iptables ===')
#    putline('\033[0m' '<code>')

    for chain in table.chains:

        putline('\033[0m' + "* Chain " + chain.name)
        if len(chain.name) >= 0:
            putline('\033[0m' + " ** Not rules defined")
        for rule in chain.rules:
            print "Rule", "proto:", rule.protocol, "src:", rule.src, "dst:", rule.dst, "in:", rule.in_interface, "out:", rule.out_interface,

            putline('\033[0m' + "* Matches: " + chain.name)
            for match in rule.matches:
                putline('\033[0m' + match.name)
#                print match.name,
            print "Target:",
            print rule.target.name

#    putline('\033[0m' '</code>')


def funcoes_habilitadas():
    '''functions enabled'''
    header()
    show_cpu()
    show_memory()
    show_partitions()
    list_interfaces()
    show_chkconfig()
    check_iptables()


def main(argv):
    '''running functions'''
    os.system('clear')
    funcoes_habilitadas()
    print '\nReport generated in:', reporttxt

if __name__ == "__main__":
    main(sys.argv[1:])
