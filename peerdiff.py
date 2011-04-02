#!/usr/bin/env python
""" peerdiff.py v0.1

    This script compares the neighbors in your router config to the RPSL-specified peers in the whois info, and shows you the discrepancies between the two. 
    For help on usage, run with -h
    
    copyleft dunamis@wheel.sh, all rights reversed.
    
"""
import sqlite3
import re
import sys
import subprocess
import getopt
import os
import socket

""" config """
conf = { 
    # sqlite3 database file to use
    'db_file': '/tmp/peerdiff.db',
    # router configuration file to read
    'router_conf': '/usr/local/etc/quagga/bgpd.conf',
    # path to the whois binary """
    'whois_bin' : '/usr/bin/whois',
    # default whois server to use """
    'whois_serv' : 'whois.ripe.net',
    # AS number to query """
    'asno' : '12345',
    # leave the database file in place after quit? """
    'keep_db' : False
}

""" databse wrapper object """
db = {
    'conn': None,
    'cursor': None
}

command = 'all'

""" =============================================================
    there's no stuff to configure below this point, except if you
    want to modify the script itself.
    =============================================================
"""

def usage():
    """
        print the help message and quit
    """
    print "This script updates an sqlite3 database containing peering info from config files and whois. The database can then be queried through the script to find discrepancies."
    print ""
    print "Usage: %s [-r router_config] [-d sqlite3_db] [-a asno] [-s whois_server] [-c] command" % sys.argv[0]
    print "-r specifies the router config file to parse for peers (Cisco/quagga syntax). Comma-separated list for multiple files."
    print "-d specifies the sqlite3 db file to use"
    print "-a specifies the asno, for use in whois"
    print "-s specifies the whois server to use"
    print "-k keep the temporary db file. It is emptied upon run however."
    print "-c prints the config"
    print "-h prints this message"
    print ""
    print "Command can be one of:"
    print "\trouter\tupdate the db with peers from router config"
    print "\twhois\tupdate the db with peers from whois db" 
    sys.exit(1)
    
def print_config():
    """
        print the current config and quit
    """
    global conf
    for s in conf:
        print "%s: %s" % (s, conf[s])
    sys.exit(0)
    
def init_db():
    """
        initialize the database, create tables if necessary
    """
    global conf,db
    
    try:
        conn = sqlite3.connect(conf['db_file'])
    except sqlite3.OperationalError,e:
        print "Could not open db file %s" % conf['db_file']
        sys.exit(1)

    cursor = conn.cursor()
    try:
        cursor.execute('CREATE TABLE router (asno int, description varchar(255), ip varchar(255))')
        cursor.execute('CREATE TABLE whois (asno int, accept varchar(255))')
    except sqlite3.OperationalError,e:
        cursor.execute('DELETE FROM router')
        cursor.execute('DELETE FROM whois')
    
    db['conn'] = conn
    db['cursor'] = cursor
    
def cleanup_db():
    """ 
        cleanup the database after we're done with it 
    """
    global conf,db
    
    db['conn'].close()

    if conf['keep_db'] != True:
        os.remove(conf['db_file'])
    
def readconfig(file):
    """
        read the router config files
    """
    global conf, db
    
    try:
        f = open(file, 'r')
        content = f.read()
    except IOError:
        print "Could not open or read from %s" % file
        sys.exit(1)

    r = re.compile(r'^\sneighbor\s+(\d.+)\s+remote-as\s+(\d+)')

    added = 0

    for line in content.split('\n'):
        groups = r.findall(line)
        if groups != []:
            asno = int(groups[0][1])
            ip = groups[0][0]
            set = None
            for line2 in content.split('\n'):
                # search for the as-set
                r2 = re.compile(r'^\sneighbor\s'+ip+r'\sdescription\s(.+)$')
                group2 = r2.findall(line2)
                if group2 != []:
                    set = group2[0]
        
            if set == None:
                print "Could not find description for AS %d at %s" % (asno, ip)
                continue

            db['cursor'].execute( 'INSERT INTO router (asno,description,ip) VALUES (?, ?, ?)', ( asno, set, ip))
            added = added + 1
            db['conn'].commit()

    print "Imported %d peers from %s" % (added, file)

def readwhois():
    global conf,db
    
    cmdline = "/usr/bin/env whois -h %s AS%s" % (conf['whois_serv'], conf['asno'])
    t = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE)
    whois = t.communicate()[0].split('\n')

    start = False
    start_re = re.compile(r'^aut-num:\s+AS%s' % conf['asno'])   # start looking for imports after this line was matched
    import_re = re.compile(r'^import:\s+from\s+AS(\d+)(\s+accept\s+(.+))?') # a peer is described by this line

    added = 0

    for line in whois:
        if start_re.match(line) != None:
            start = True
        if not start:
            continue
        import_m = import_re.match(line)
        if import_m != None:
            asno = int(import_m.group(1))
            accept = import_m.group(3)
            db['cursor'].execute('INSERT INTO whois (asno, accept) VALUES(?, ?)', (asno, accept))
            db['conn'].commit()
            added = added + 1
            
    print "Imported %d peers from whois" % added
    
def compare():
    global conf,db
    res = db['cursor'].execute('select router.asno, router.description, whois.accept, router.ip from router left join whois on whois.asno=router.asno')
    for line in db['cursor'].fetchall():
        in_whois = line[2]
        if in_whois == None:
            print "Peer AS%s(%s) is in router config (%s) but not in RPSL" % (line[0], line[1], line[3])

    res = db['cursor'].execute('select whois.asno, whois.accept, router.description from whois left join router on whois.asno=router.asno;')
    for line in db['cursor'].fetchall():
        in_router = line[2]
        if in_router == None:
            print "Peer AS%s(%s) is in whois but not in router config" % (line[0], line[1])
    
def main():
    """
        main function
    """
    global conf,db,command
    
    try:
        optlist, args = getopt.getopt( sys.argv[1:], 'd:r:ha:cks:')
    except getopt.GetoptError, er:
        usage()

    if len(args) == 1:
        command = args[0]
    elif len(args) > 1:
        usage()

    for opt in optlist:
        if opt[0] == '-h':
            usage()
        elif opt[0] == '-c':
            print_config()
        elif opt[0] == '-d':
            conf['db_file'] = opt[1]
        elif opt[0] == '-r':
            conf['router_conf'] = opt[1]
        elif opt[0] == '-a':
            asno_re = re.compile(r'^[\w\d]+$')
            m = asno_re.match(opt[1])
            if m:
                conf['asno'] = opt[1]
            else:
                sys.stderr.write("Invalid asno, must be ^[]\w\d]+$\n")
                sys.exit(1)
        elif opt[0] == '-s':
            try:
                socket.gethostbyname(opt[1])
                conf['whois_serv'] = opt[1]
            except socket.gaierror:
                sys.stderr.write("Invalid whois server given, could not resolve\n")
                sys.exit(1)
                pass
        elif opt[0] == '-k':
            conf['keep_db'] = True

    init_db()

    if command == 'all' or command == 'update-router':
        files = conf['router_conf'].split(',')
        for f in files:
            print f
            readconfig(f)
    
    if command == 'all' or command == 'update-whois':
        readwhois()
    
    if command == 'all' or command == 'compare':
        compare()
        
    cleanup_db()

if __name__ == '__main__':
    main()

