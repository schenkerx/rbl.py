# /usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import urllib2
import argparse

rbls = [
    'b.barracudacentral.org',
    'cbl.abuseat.org',
    'http.dnsbl.sorbs.net',
    'misc.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'web.dnsbl.sorbs.net',
    'dnsbl-1.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'sbl.spamhaus.org',
    'zen.spamhaus.org',
    'psbl.surriel.com',
    'dnsbl.njabl.org',
    'rbl.spamlab.com',
    'noptr.spamrats.com',
    'cbl.anti-spam.org.cn',
    'dnsbl.inps.de',
    'httpbl.abuse.ch',
    'korea.services.net',
    'virus.rbl.jp',
    'wormrbl.imp.ch',
    'rbl.suresupport.com',
    'ips.backscatterer.org',
    'opm.tornevall.org',
    'multi.surbl.org',
    'tor.dan.me.uk',
    'relays.mail-abuse.org',
    'rbl-plus.mail-abuse.org',
    'access.redhawk.org',
    'rbl.interserver.net',
    'bogons.cymru.com',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'dul.dnsbl.sorbs.net',
    'smtp.dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'zombie.dnsbl.sorbs.net',
    'dnsbl-2.uceprotect.net',
    'pbl.spamhaus.org',
    'xbl.spamhaus.org',
    'bl.spamcannibal.org',
    'ubl.unsubscore.com',
    'combined.njabl.org',
    'dyna.spamrats.com',
    'spam.spamrats.com',
    'cdl.anti-spam.org.cn',
    'drone.abuse.ch',
    'dul.ru',
    'short.rbl.jp',
    'spamrbl.imp.ch',
    'virbl.bit.nl',
    'dsn.rfc-ignorant.org',
    'dsn.rfc-ignorant.org',
    'netblock.pedantic.org',
    'ix.dnsbl.manitu.net',
    'rbl.efnetrbl.org',
    'blackholes.mail-abuse.org',
    'dnsbl.dronebl.org',
    'db.wpbl.info',
    'query.senderbase.org',
    'bl.emailbasura.org',
    'combined.rbl.msrbl.net',
    'multi.uribl.com',
    'black.uribl.com',
    'cblless.anti-spam.org.cn',
    'cblplus.anti-spam.org.cn',
    'blackholes.five-ten-sg.com',
    'sorbs.dnsbl.net.au',
    'rmst.dnsbl.net.au',
    'dnsbl.kempt.net',
    'blacklist.woody.ch',
    'rot.blackhole.cantv.net',
    'virus.rbl.msrbl.net',
    'phishing.rbl.msrbl.net',
    'images.rbl.msrbl.net',
    'spam.rbl.msrbl.net',
    'spamlist.or.kr',
    'dnsbl.abuse.ch',
    'bl.deadbeef.com',
    'ricn.dnsbl.net.au',
    'forbidden.icm.edu.pl',
    'probes.dnsbl.net.au',
    'ubl.lashback.com',
    'ksi.dnsbl.net.au',
    'uribl.swinog.ch',
    'bsb.spamlookup.net',
    'dob.sibl.support-intelligence.net',
    'url.rbl.jp',
    'dyndns.rbl.jp',
    'omrs.dnsbl.net.au',
    'osrs.dnsbl.net.au',
    'orvedb.aupads.org',
    'relays.nether.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'dialups.mail-abuse.org',
    'rdts.dnsbl.net.au',
    'duinv.aupads.org',
    'dynablock.sorbs.net',
    'residential.block.transip.nl',
    'dynip.rothen.com',
    'dul.blackhole.cantv.net',
    'mail.people.it',
    'blacklist.sci.kun.nl',
    'all.spamblock.unit.liu.se',
    'spamguard.leadmon.net',
    'csi.cloudmark.com'
]


def check_rbl(target_ip):
    # Reverse target IP address
    reverse_ip = '.'.join(target_ip.split('.')[::-1])
    ban_list = []
    for rbl in rbls:
        try:
            socket.getaddrinfo(reverse_ip + '.' + rbl, 25)
            ban_list.append(rbl)
        except socket.gaierror as dnserr:
            pass

    return ban_list


def get_external_ip():
    # For compatibility of argparse
    return [urllib2.urlopen('http://ip.42.pl/raw').read()]


def main():
    argparser = argparse.ArgumentParser(
        prog='rbl.py',
        description='email server reputation checker'
    )
    argparser.add_argument(
        '-a',
        '--ip',
        nargs=1,
        default=get_external_ip(),
        help='IP address to check (default: your public IP address)'
    )
    args = argparser.parse_args()
    for ip in args.ip:
        rbl_result = check_rbl(ip)
        if rbl_result:
            print('Result for {0}:'.format(ip))
            for res in rbl_result:
                print('Banned by {0}'.format(res))
            print('')


if __name__ == '__main__':
    main()
