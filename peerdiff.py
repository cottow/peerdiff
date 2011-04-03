#!/usr/bin/env python
""" peerdiff.py v0.1

    This script compares the neighbors in your router config to the RPSL-specified peers in the whois info, and shows you the discrepancies between the two. It formats the entries that are not in WHOIS yet in RPSL, guessing the announced AS-set from the set announced to you by the peer (if it can be found).

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
    # default AS set to announce
    'default_set' : 'AS-REPLACEME',
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
    print "-r\t specifies the router config file to parse for peers (Cisco/quagga syntax). Comma-separated list for multiple files."
    print "-d\t specifies the sqlite3 db file to use"
    print "-a\t specifies the asno, for use in whois"
    print "-s\t specifies the whois server to use"
    print "-n\t specifies the AS-set to announce (used in pretty output only)"
    print "-k\t keep the temporary db file. It is emptied upon run however."
    print "-c\t print the config and exit"
    print "-h\t prints this message"
    print ""
    print "Command can be one of:"
    print "\tupdate-router\tupdate the db with peers from router config"
    print "\tupdate-whois\tupdate the db with peers from whois db"
    print "\tcompare\tcompare the info in the db and print discrepancies"
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
        cursor.execute('CREATE TABLE router (asno int unique, ip varchar(255), peergroup varchar(255))')
        cursor.execute('CREATE TABLE whois (asno int unique, accept varchar(255))')
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

    r = re.compile(r'neighbor\s+(\d.+)\s+remote-as\s+(\d+)')
    added = 0

    for line in content.split('\n'):
        groups = r.findall(line)
        if groups != []:
            asno = int(groups[0][1])
            ip = groups[0][0]
            peergroup = ''
            mre = r'^\s*neighbor\s+'+ip+r'\s+peer-group\s+(\S+)'
            peer_re = re.compile(mre)
            for line2 in content.split('\n'):
                # find peer group
                peer_m = peer_re.match(line2)
                if peer_m != None:
                    peergroup = peer_m.group(1)
                    break
            try:
                db['cursor'].execute( 'INSERT INTO router (asno,ip, peergroup) VALUES (?, ?, ?)', ( asno, ip, peergroup))
                db['conn'].commit()

            except sqlite3.IntegrityError:
                # already in db, fine.
                pass
            added = added + 1
            
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
            if accept == None:
                accept = 'Unknown'
            try:
                db['cursor'].execute('INSERT INTO whois (asno, accept) VALUES(?, ?)', (asno, accept))
                db['conn'].commit()
            except sqlite3.IntegrityError:
                pass

            added = added + 1
            
    print "Imported %d peers from whois" % added
   
def get_asinfo(asno):
    """
        get a descriptive name for an asno
    """
    global conf
    cmdline = "/usr/bin/env whois AS%s" % (asno)
    t = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE)
    whois = t.communicate()[0].split('\n')

    start = False
    start_re = re.compile(r'^aut-num:\s+AS%s' % asno)   # start looking for imports after this line was matched
    import_re = re.compile(r'^import:\s+from\s+AS(\d+)(\s+accept\s+(.+))?') # a peer is described by this line
    descr_re = re.compile(r'^descr:\W+(\w.*)') # company name, probably
    asset_re = re.compile(r'^export:.*AS%s.*announce\s(\S+)' % conf['asno'])
    asset = ''
    asname = ''

    for line in whois:
        if start_re.match(line) != None:
            start = True
        if not start:
            continue
        if asset != '' and asname != '':
            break
        descr_m = descr_re.match(line)
        asset_m = asset_re.match(line)
        if descr_m != None and asname == '':
            # matched company name
            asname = descr_m.group(1)
        if asset_m != None and asset == '':
            # matched as-set
            asset = asset_m.group(1)

    if asset == '':
        asset = 'ANY'
    return (asname,asset)

def compare():
    """
        compare the whois and router peer sets and prints discrepancies
    """
    global conf,db
    res = db['cursor'].execute('select router.asno, whois.accept, router.ip from router left join whois on whois.asno=router.asno')
    print "---- In router config, but not in WHOIS:"
    diffs = 0

    for line in db['cursor'].fetchall():
        in_whois = line[1]
        if in_whois == None:
            diffs = diffs + 1
            (asname,asset) = get_asinfo(line[0])
            print "remarks: ----- %s " % asname
            print "import: from AS%s accept %s" % (line[0], asset)
            print "export: to AS%s announce %s" % (line[0], conf['default_set'])
    print ""
    print "---- In WHOIS, but not in router config:"
    res = db['cursor'].execute('select whois.asno, whois.accept, router.ip from whois left join router on whois.asno=router.asno;')
    for line in db['cursor'].fetchall():
        diffs=  diffs + 1
        in_router = line[2]
        if in_router == None:
            print "AS%s (accept %s)" % (line[0], line[1])

    if diffs == 0:
        print "No differences between router config and whois."
    else:
        print ""
        print " -- warning -- the above output should not be submitted directly to a RIR DB, but checked first for nonsense. For example, filter out your ibgp peers. Also, the AS-set that is accepted from each peer is set to ANY if no export was found at the peer, please fix if you have stricter filtering." 

def main():
    """
        main function
    """
    global conf,db,command
    
    try:
        optlist, args = getopt.getopt( sys.argv[1:], 'd:r:ha:n:cks:')
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
        elif opt[0] == '-n':
            conf['default_set'] = opt[1]
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
            readconfig(f)
    
    if command == 'all' or command == 'update-whois':
        readwhois()
    
    if command == 'all' or command == 'compare':
        compare()
        
    cleanup_db()

if __name__ == '__main__':
    main()

