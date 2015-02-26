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
from datetime import datetime


osdistro = platform.dist()
distro = osdistro[0].lower()

hostname = socket.gethostname()
tag = datetime.now().strftime('%y.%m.%d_%H.%M')
reporttxt = ('/tmp/%s_%s.txt' % (hostname, tag))

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
    putline('=== CPU ===')
    putline('Total cpus: ' + str(number_cpus))


def show_memory():
    '''Displays amount of memory'''
    putline('')
    putline('=== Memory ===')
    uso_memory = psutil.virtual_memory()
    total_swap = psutil.swap_memory()
    putline('Memory: ' +
            str(convert_bytes(uso_memory[0])))
    putline(' ')
    putline('swap: ' + str(convert_bytes(total_swap[0])))


def show_partitions():
    ''' Show partitions '''
    partitions = psutil.disk_partitions()
    putline('')
    putline('=== Mount Points ===')

    putline("^Device ^ Mount Point ^FileSystem ^ Options ^ ")
    for item in partitions:
        putline('|' + str(item[0]) + '|' + str(
            item[1]) + '|' + str(item[2]) + '|' + str(item[3]) + '|')


def list_interfaces():
    '''list network interfaces'''

    putline('')
    putline('=== Interfaces ===')

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

    def get_default_gateway():
        """Read the default gateway directly from /proc."""
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

    ifs = all_interfaces()
    gw = get_default_gateway()

    putline("^Interface ^ Address ^")
    for i in ifs:
        putline("| %1s | %s |" % (i[0], format_ip(i[1])))

    putline("| Default gateway | %s | " % gw)


def show_chkconfig():
    '''Displays the services enabled at startup'''
    putline('')
    putline('=== Services enabled at startup ===')

    if 'centos' in distro:
        servicescentos = []
        chkconfigon = os.popen('chkconfig |grep 3:on |awk \'{print $1}\'')
        for line in chkconfigon:
            servicescentos.append(line.strip())
        putline(str(servicescentos))

    elif "ubuntu" == distro:
        serviceschk = []
        services_running_ubuntu = os.popen('/sbin/initctl list |grep running')
        for line in services_running_ubuntu:
            serviceschk.append(line.replace('start/running,', '').strip())

        for servicosrodando in serviceschk:
            #ServicosRodando.replace('start/running,', '')
            putline('' + '  *  ' + servicosrodando)
    elif "gentoo" == distro:
        servicesgentoo = []
        services_running_gentoo = os.popen("rc-status |grep started |awk {'print $1'}")

        for line in services_running_gentoo:
            servicesgentoo.append(line.strip())

        for servicesenabledgentoo in servicesgentoo:
            putline(" * "+ str(servicesenabledgentoo))

    else:
        putline(" * distro unknown ")

def crontab():
    ''' Show crontab on system'''

    import os.path
    putline('')
    putline('=== crontab ===')

    dir_crons = ['/etc/cron.d/',
    '/etc/cron.daily/',
    '/etc/cron.deny/',
    '/etc/cron.hourly/',
    '/etc/cron.monthly/',
    '/etc/cron.weekly/']

    for dirs in dir_crons:
        if os.path.exists(dirs) is True:
            for file in os.listdir(dirs):
                fullpath = dirs+file
                putline('File: ' + fullpath + '\n')
                putline('<code>')
                file1 = open(fullpath, "r").read()
                putline(file1)
                putline('</code>')

def check_iptables():
    '''List the rules of iptables'''
    import iptc
    table = iptc.Table(iptc.Table.FILTER)

    putline('')
    putline('=== Iptables ===')
#    putline('<code>')

    for chain in table.chains:

        putline("* Chain " + chain.name)
        if len(chain.name) >= 0:
            putline(" ** Not rules defined")
        for rule in chain.rules:
            putline("Rule")
            putline("Protocol: ^ source ^ destination ^ in: ^ out ^ ")
            putline("|" + rule.protocol + "|" + rule.src +  "|" + rule.dst + "|" + rule.in_interface + "|" +  str(rule.out_interface))

            putline("* Matches: " + chain.name)
            for match in rule.matches:
                putline(match.name)
            putline("Target:")
            putline(rule.target.name)

#    putline('</code>')


def funcoes_habilitadas():
    '''functions enabled'''
    header()
    show_cpu()
    show_memory()
    show_partitions()
    list_interfaces()
    show_chkconfig()
    check_iptables()
    crontab()

def main(argv):
    '''running functions'''
    os.system('clear')
    funcoes_habilitadas()
    print '\nReport generated in:', reporttxt

if __name__ == "__main__":
    main(sys.argv[1:])

