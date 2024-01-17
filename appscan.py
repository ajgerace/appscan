from flask import Flask, request
import sqlite3, sys, os, dominate, pathlib, datetime
import pandas as pd
import plotly.express as px
import html, json, xmltodict, base64, re, requests
from dominate.tags import *
from dominate import tags as tags

# Init app
app = Flask(__name__, static_folder='static', static_url_path='')


version = "1.1.2.13"


def request_bearer_token(oauth_client, oauth_secret):

  u_auth_coded = base64.b64encode(bytes(oauth_client + ':' + oauth_secret, 'utf-8'))
  u_auth = u_auth_coded.decode()
  if u_auth == None:
    print('Error: Missing API_KEY environment variable, exiting ...')
    sys.exit()
    
  auth_url = "https://identity.account.f5.com/oauth2/ausp95ykc80HOU7SQ357/v1/token"

  auth_headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'authorization': 'Basic ' + str(u_auth),
    'cache-control': 'no-cache',
    'accept': 'application/json'
  }    
  data = {'grant_type': 'client_credentials', 'scope': 'ihealth'}
  response = requests.post(auth_url, headers=auth_headers, data=data)

  if response.status_code == 200:
      token_data = response.json()
      return token_data['access_token']
  else:
      print(f"Error: {response.status_code}")
      sys.exit()

############################### decodeQkviewCommands #################################
def decodeQkviewCommands(responseText):
  dictOut = xmltodict.parse(responseText)
  encoded = dictOut['commands']['command']['output']
  if len(encoded) % 4 == 3:
    encoded += '='
  elif len(encoded) % 4 == 2:
    encoded += '=='
  decoded =  base64.b64decode(encoded).decode(encoding='UTF-8')
  return decoded



############################### parsePools #####################################

def parsePools(conn, poolLines):
    cursor = conn.cursor()
    index = 0
    maxpoolLines = len(poolLines)
    line = poolLines[index]
    while index < maxpoolLines:
       line = poolLines[index] 
       if 'ltm pool ' in line:
        lbMethod = "round-robin"
        poolDescription = ""
        monitorName = ""
        monList=[]
        slowRamp = 0
        fields = poolLines[index].split(' ')
        poolName = fields[2]
        index += 1
        line = poolLines[index]
        while not line.startswith('}\n'):
            if 'load-balancing' in line:
                fields = line.split('mode ')
                lbMethod = fields[1].strip()
            elif 'description' in line:
                if '&quot' in line: 
                    fields = line.replace('&quot;','\"').split('tion ')
                else:
                    fields = line.split('tion ')
                    poolDescription = fields[1].strip()
            elif 'monitor' in line:
                if ' of ' in line:
                    fields = line.split(' of ')
                    if ' ' in fields[1]:
                        monList = fields[1].strip().split(' ')
                    else:
                        monList.append(fields[1].strip())
                else:
                    fields = line.strip().split(' ')
                    monList.append(fields[1].strip())   
            elif 'slow-ramp' in line:
                fields = line.split('time ')
                slowRamp = fields[1].strip()
            elif 'members {' in line:
                index += 1
                line = poolLines[index]
                poolMembers = ''
                poolMemEntry={}
                while line != '    }\n':
                    fields = line.split(' {')
                    mem = fields[0].strip()
                    (memName, memPort) = mem.split(':')
                    index += 1
                    line = poolLines[index]
                    memDesc = ""
                    memMon = ""
                    memSessionStatus = "enabled"
                    memSessionState = "up"
                    
                    while line != '        }\n':
                        if 'address ' in line:
                            fields = line.split('address ')
                            memAddr = fields[1].strip()
                        elif 'session user ' in line:
                            memSessionStatus = 'disabled'
                        elif 'state user-down' in line:
                            memSessionState =  "forced down"
                        index += 1
                        line = poolLines[index]
                    index += 1
                    line = poolLines[index]
                    poolMemEntry[mem] = {}
                    poolMemEntry[mem]['name'] = memName
                    poolMemEntry[mem]['address']= memAddr
                    poolMemEntry[mem]['port'] = memPort
                    poolMemEntry[mem]['sessionState'] = memSessionStatus
                    poolMemEntry[mem]['availabilityState'] = memSessionState

            elif 'members none' in line:
                poolMembers = 'none'
            elif 'partition' in line:
                entry = line.split('partition')
                partition = entry[1].strip()
                if not partition in poolName:
                    pName = poolName
                    poolName = '/' + partition + '/' + pName 
            index += 1
            line = poolLines[index]
        if len(monList) > 0:
            for mon in monList:
                if mon.count('/') == 3: 
                    monitorName = mon 
                else:
                    monitorName = '/Common/' + mon
                print('Insert into pool_monitor table ',poolName, monitorName)
                cursor.execute("insert into pool_monitor_tbl('poolName', 'monitorName') values (?,?)", (poolName, monitorName ))
                conn.commit()

        if poolMembers == '':
            for mem in poolMemEntry:
                memName = '/' + partition + '/' + poolMemEntry[mem]['name']
                memPort = poolMemEntry[mem]['port']
                memAddr = poolMemEntry[mem]['address']
                memSession = poolMemEntry[mem]['sessionState']
                memAvail = poolMemEntry[mem]['availabilityState']
                print('Insert into member table ', poolName, memName, memPort, memAddr, memSession, memAvail)
                cursor.execute("insert into member_tbl ('poolName', 'memberName', 'memberPort', 'memberAddress', 'sessionState', 'availabilityState') values (?,?,?,?,?,?)", (poolName, memName, memPort, memAddr, memSession, memAvail))
                conn.commit()
        
        print('Insert into pool table ', poolName, poolDescription, lbMethod, slowRamp)   
        index += 1
        
        cursor.execute("INSERT INTO pool_tbl ('poolName', 'poolDescription', 'lbMethod',  'slowRamp' ) VALUES (?,?,?,?)", ( poolName, poolDescription, lbMethod, slowRamp ))    
        conn.commit()

############################### parseRules #################################
def parseRules(conn, lines):
  cursor = conn.cursor()
  for rule in lines:
    if rule == '':
       continue
    ruleName, ruleBody  = rule.split(' ', 1)
#   ruleDef = html.unescape(ruleBody)
    ruleDef = ruleBody.replace('&quot;','\"')
    ruleLength = ruleDef.count('\n')
    cursor.execute("INSERT INTO irules_tbl ('ruleName', 'ruleDefinition', 'ruleLength') VALUES (?,?,?)", (ruleName, ruleDef, ruleLength))
    conn.commit()

############################### parseVirtuals #################################
def parseVirtuals(conn, lines):
    cursor = conn.cursor()
    vsIndex = 0
    maxlines = len(lines)
    apmProfiles = ('ppp','rba','remotedesktop', 'vdi', 'websso')    
    while vsIndex < maxlines:
       line = lines[vsIndex]
       if 'ltm virtual ' in line:
          
            vsName = ""
            descript = ""
            vip = ""
            clientSSLprofile = ""
            serverSSLprofile = ""
            tcpProfile = ""
            HTTPprofile = ""
            ipProtocol = "tcp"
            persistName = ""
            vsPolicyList = [ 'none']
            apmEnabled = 'false'
            wafEnabled = 'false'
            poolName = ""
            rulesInUse = 0
            entries = lines[vsIndex].split(' ')
            vsName = entries[2]
            vsIndex += 1
            line = lines[vsIndex]
            while not line.startswith('}\n'):
                if line.startswith('    description'):
                    fields = lines[vsIndex].split('ion ')
                    descript = fields[1].strip()
                elif line.startswith('    destination'):
                    fields = line.strip().split(' ')
                    vsAddr, vsPort = fields[1].split(':')        
                elif line.startswith('    fallback-persistence') and not line.endswith('none'):
                    gb, fallbackPersistName = line.strip().split('ence ')
                elif line.startswith('    ip-proto'):
                    fields = line.split('col ')
                    ipProtocol = fields[1].strip()
                elif line.startswith('    persist none'):
                    persistName ='none'
                elif line.startswith('    persist '):
                    vsIndex += 1
                    line = lines[vsIndex].strip()
                    persistName, gb = line.split(' ')
                elif line.startswith('    policies {'):
                    vsIndex += 1
                    line = lines[vsIndex]
                    vsPolicyList = []
                    while line != '    }\n':
                        fields = line.split(' {')
                        polName = fields[0].rstrip()
                        if 'asm' in polName:
                            wafEnabled = 'true'
                            vsPolicyList.append(polName)
                        vsIndex += 1
                        line = lines[vsIndex]
                elif line.startswith('    pool'):
                    fields = line.split('pool ')
                    poolName = fields[1].rstrip()
                elif line.startswith('    profiles'):
                    vsIndex += 1
                    line = lines[vsIndex]
                    while line != '    }\n':
                        if line.startswith('        /'):
                            entries = line.strip().split(' {')
                            profileName = entries[0]
                        if line.endswith('{ }\n'):
                            profileContext = 'both'
                        elif line.endswith('{\n'):
                            vsIndex += 1
                            if 'context' in lines[vsIndex]:
                                gb, profileContext = lines[vsIndex].strip().split('context ')
                            if profileName.endswith(apmProfiles):
                                apmEnabled = 'true'
                        print('Insert into vs_profile_tbl: ', vsName, profileName, profileContext)
                        cursor.execute("insert into vs_profile_tbl ('vsName', 'profileName', 'profileContext') values (?,?,?)", (vsName, profileName, profileContext))
                        vsIndex += 1
                        line = lines[vsIndex]     
                elif line.startswith('    rules {'):
                    vsIndex += 1
                    line = lines[vsIndex]
                    rulesInUse = 0
                    while line != '    }\n':
                        fields = line.split(' {')
                        ruleName = fields[0].strip()
                        rulesInUse +=1
                        print('Insert into vs_irule_tbl: ', vsName, ruleName)
                        cursor.execute("insert into vs_irule_tbl ('vsName', 'ruleName') values (?,?)", (vsName, ruleName))
                        vsIndex += 1
                        line = lines[vsIndex]
                elif line.startswith('    source-address-trans'):
                    vsIndex += 1
                    line = lines[vsIndex]
                    if line.endswith(' none\n'):
                        snatPool = 'none'
                        vsIndex += 1
                        line = lines[vsIndex].strip()
                        gb, snatType = line.split('type ')
                    else:
                        gb,snatPool = line.split('pool ')
                        vsIndex += 1
                        line = lines[vsIndex].strip()
                        gb, snatType = line.split('type ')

                vsIndex += 1
                line = lines[vsIndex]
            policyStr = ';'.join(vsPolicyList)                    
            vsIndex += 1
#            line = lines[vsIndex]
            
            print('Insert into vs_tbl: ', vsName, vsAddr, vsPort, descript, ipProtocol, persistName, policyStr, poolName, apmEnabled, wafEnabled,  rulesInUse, snatPool, snatType, fallbackPersistName)
       cursor.execute("INSERT INTO vs_tbl ('vsName', 'vsAddr', 'vsPort', 'description', 'ipProtocol', 'persistName',	'trafficPolicy',	'poolName', 'apmEnabled', 'wafEnabled', 'ruleCount',	'snatPool', 'snatType', 'fallbackPersistName') VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (vsName, vsAddr, vsPort, descript, ipProtocol, persistName, policyStr, poolName, apmEnabled, wafEnabled,  rulesInUse, snatPool, snatType, fallbackPersistName))
       conn.commit()

############################### parseClientSSL #################################
def parseClientSSL(conn, lines):
  cursor = conn.cursor()
  cIndex = 0
  maxLines = len(lines)
  while cIndex < maxLines:
    line = lines[cIndex]
    fields = line.split(' ')
    clientSSLName = fields[3]
    cIndex += 1
    line = lines[cIndex]
    while not line.startswith('}\n'):
        if line.startswith('    cert '):
            key, certName = line.strip().split(' ')
        elif line.startswith('    chain '):
            key, chain = line.strip().split(' ')
        elif line.startswith('    ciphers '):
            key, ciphers = line.strip().split(' ')
        elif line.startswith('    key '):
            k, keyName = line.strip().split(' ')
        elif line.startswith('    server-name '):
            key, serverName = line.strip().split(' ')
        cIndex += 1
        line = lines[cIndex]
    cIndex +=1
    print('Insert into clientssl_tbl: ', clientSSLName, certName, chain, ciphers, keyName, serverName)
#    clientSSL_Profiles[clientSSLName] = clientSSLName
    cursor.execute("INSERT INTO clientssl_tbl ('clientsslName', 'certName',	'chainName', 'cipher',	 'keyName', 'serverName') VALUES (?,?,?,?,?,?)", (clientSSLName, certName, chain, ciphers, keyName, serverName))
    conn.commit()

############################### parseHTTP#################################
def parseHTTP(conn, lines):
  cursor = conn.cursor() 
  hIndex = 0
  maxLines = len(lines)
  while hIndex < maxLines:
    line = lines[hIndex]
    fields = line.split(' ')
    HTTPname = fields[3]   
    while line != '}\n':
        if line.startswith('    header-erase'):
            key, headerErase = line.strip().split(' ',1)
        elif line.startswith('    header-insert'):
            key, headerInsert = line.strip().split(' ',1)
        elif line.startswith('    insert-xforward'):
            key, value = line.strip().split(' ')
            if value == 'enabled':
                insertXFF = 'True'
            else:
                insertXFF = 'False'
        hIndex += 1
        line = lines[hIndex]
    hIndex += 1
    print('Insert into http_tbl: ', HTTPname, headerErase, headerInsert, insertXFF)
  
    cursor.execute("INSERT INTO http_tbl ('httpName', 'headerErase', 'headerInsert', 'insertXFF') VALUES (?,?,?,?)", (HTTPname, headerErase, headerInsert, insertXFF))
    conn.commit()


################################ parseServerSSL #################################
def parseServerSSL(conn, lines):
  cursor = conn.cursor()
  sIndex = 0
  maxLines = len(lines)
  while sIndex < maxLines:
    line = lines[sIndex]
    fields = line.split(' ')
    serverSSLName = fields[3]
    sIndex += 1
    line = lines[sIndex]
    while line != '}\n':
        if line.startswith('    cert '):
            key, cert = line.strip().split(' ')
        elif line.startswith('    chain '):
            key, chain = line.strip().split(' ')
        elif line.startswith('    ciphers '):
            key, ciphers = line.strip().split(' ')
        elif line.startswith('    key '):
            k, key = line.strip().split(' ')
        elif line.startswith('    peer-cert-mode '):
            key, peerCertMode = line.strip().split(' ')
        sIndex += 1
        line = lines[sIndex]
    sIndex += 1
    print('Insert into serverssl_tbl: ',serverSSLName, cert, chain, ciphers, key, peerCertMode )
  cursor.execute("INSERT INTO serverssl_tbl ('serverSSLName', 'certName', 'chainName', 'cipher', 'keyName',	'peerCertMode' ) VALUES (?,?,?,?,?,?)", (serverSSLName, cert, chain, ciphers, key, peerCertMode))
  conn.commit()

################################ parseTCP #################################
def parseTCP(conn, lines):
  tIndex =0
  maxLines = len(lines)
  while tIndex < maxLines:
    line = lines[tIndex]
    fields = line.split(' ')
    TCPname = fields[3]
    tIndex += 1
    line = lines[tIndex]
    while line != '}\n':
        if line.startswith('    idle-time'):
            key, idleTimeout = line.strip().split(' ')
        tIndex += 1
        line = lines[tIndex]
    tIndex += 1
    print('Insert into tcp_tbl: ', TCPname, idleTimeout)
  cursor = conn.cursor()  
  cursor.execute("INSERT INTO tcp_tbl ('tcpName', 'idleTimeout') VALUES (?,?)", (TCPname, idleTimeout))
  conn.commit()  

################################ parseMonitors #################################
def parseMonitors(conn, lines):
  mIndex = 0
  maxLines = len(lines)
  while mIndex < maxLines:
    line = lines[mIndex]
    if 'ltm monitor ' in line:
        interval    = 15
        timeout     = 31
        recv        = ''
        send        = ''
        key         = ''
        cert        = ''
        cipherList  = ''
        fields = line.split(' ')
        monType = fields[2]
        monName = fields[3]
        mIndex += 1
        line = lines[mIndex]
        while line != '}\n':
            line = lines[mIndex]
            if line.startswith('    cert'):
                gb, cert = line.strip().split(' ')
            elif line.startswith('    cipher'):
                gb, cipherList = line.strip().split(' ')       
            elif line.startswith('    interval'):
                key, interval = line.strip().split(' ')
            elif line.startswith('    key'):
                gb, key = line.strip().split(' ')        
            elif line.startswith('    recv '):
                gb, recv = line.strip().split('recv ')
            elif line.startswith('    send '):
                entries = line.strip().split('send ')
                send = entries[1].replace('&quot;','\"')
            elif line.startswith('    timeout'):
                gb, timeout = line.strip().split(' ')
            mIndex += 1
            line = lines[mIndex]
    mIndex +=1
    print('Insert into monitor_tbl: ', monName, monType, cert, cipherList, interval, key, recv, send, timeout)
  cursor = conn.cursor()
  cursor.execute("INSERT INTO monitor_tbl ('monitorName', 'monitorType',  'monitorCert', 'monitorCipher', 'interval', 'monitorKey', 'receiveString', 'sendString', 'timeout' )   VALUES (?,?,?,?,?,?,?,?,?)", (monName, monType, cert, cipherList, interval, key, recv, send, timeout))
  conn.commit()  

############################## parseBigIpConf ########################################

def parseBigIpConf(connection, cfgFile):
  cursor = connection.cursor()
  index = 0
  eof = len(cfgFile) 
  while index < eof:
    line = cfgFile[index].rstrip()

    if 'ltm persistence ' in line:
      fields = line.split(' ')
      persistType = fields[2]
      persistName = fields[3]
      if persistType == 'cookie':
        cookieAlwaySend = "disabled"
        cookieName = "none"
        expiration = 0
        cookieEncryption = "disabled"
        method = "insert"
        httpOnly = "disabled"
        secureFlag = "disabled"
        index += 1
        line = cfgFile[index]
        while not line.startswith('}'):
          if 'always-send' in line:
              cookieAlwaySend = "enabled"
          elif 'cookie-name' in line:
              gb, cookieName = line.split('name ')
          elif 'expiration' in line:
              gb, expiration = line.split('expiration ')
          elif 'cookie-encryption ' in line:
              gb, cookieEncryption = line.split('cryption ')
          elif 'httponly' in line:
              gb, httpOnly = line.split('only ')
          elif 'method' in line:
              gb, method = line.split('method ')
          elif 'secure' in line:
              gb, secureFlag = line.split('secure ')
          index += 1
          line = cfgFile[index].rstrip()
        cursor.execute("insert into persist_tbl ('persistName', 'persistType','alwaySend', 'cookieName', 'cookieExpiration', 'cookieEncryption', 'cookieHttpOnly', 'cookieMethod', 'cookieSecure' ) values (?,?,?,?,?,?,?,?,?)", (persistName, persistType, cookieAlwaySend, cookieName, expiration, cookieEncryption, httpOnly, method, secureFlag) )
        connection.commit()    
      elif persistType == 'source-addr':
        hashAlgorithm = 'default'
        mask = 'none'
        matchAcrossPools = 'disabled'
        matchAcrossServices = 'disabled'
        matchAcrossVirtuals ='disabled'
        mirror  = 'disabled'
        overrideConnectionLimit = 'disabled'
        timeout  = 180
        index += 1
        line = cfgFile[index]
        while not line.startswith('}'):
            if 'hash-algorithm' in line:
              gb, hashAlgorithm = line.split('rithm ')
            elif 'mask' in line:
              gb, mask = line.split('mask ')
            elif 'match-across-pools' in line:
              gb, matchAcrossPools = line.split('pools ')
            elif 'match-across-services' in line:
              gb, matchAcrossServices = line.split('services ')
            elif 'match-across-virtuals' in line:
              gb, matchAcrossVirtuals = line.split('virtuals ')
            elif 'mirror' in line:
              gb, mirror = line.split('mirror ')
            elif 'override-connection-limit' in line:
              gb, overrideConnectionLimit = line.split('tion-limit ')
            elif 'timeout' in line:
              gb, timeout = line.split('timeout ')
            index += 1
            line = cfgFile[index].rstrip()
        cursor.execute("insert into persist_tbl ('persistName', 'persistType','hashAlgorithm', 'mask', 'matchAcrossPools','matchAcrossServices', 'matchAcrossVirtuals', 'mirror', 'overrideConnectionLimit', 'timeout' ) values (?,?,?,?,?,?,?,?,?,?)", (persistName, persistType,hashAlgorithm, mask, matchAcrossPools,matchAcrossServices, matchAcrossVirtuals, mirror, overrideConnectionLimit, timeout) )
        connection.commit()
    elif 'ltm monitor' in line and not 'monitor http ' in line or 'monitor tcp ' in line :
      fields = line.split(' ')
      monType = fields[2]
      monName = fields[3]
      index += 1
      line = cfgFile[index].rstrip()      
      while not line.startswith('}'):
        if line.startswith('    interval'):
          key, interval = line.strip().split(' ')
        elif line.startswith('    timeout'):
          gb, timeout = line.strip().split(' ')
        index += 1
        line = cfgFile[index].rstrip()             
      cursor.execute("INSERT INTO monitor_tbl ('monitorName', 'monitorType', 'interval', 'timeout' )   VALUES (?,?,?,?)", (monName, monType, interval, timeout))
      connection.commit()  
    elif 'ltm profile ' in line:
      fields = line.split(' ')
      profileType = fields[2]
      profileName = fields[3]
      cursor.execute("insert into profile_tbl ('profileName', 'profileType') values (?,?)", (profileName, profileType))
      connection.commit()
    index += 1
   
############################## parseStats ##############################
# sub to parse stats_module.xml 
def parseStats(conn, statsCfg):
    cursor = conn.cursor()
    dict = xmltodict.parse(statsCfg)
    vsStats = dict['Qkproc']['cluster']['virtual_server_stat']['object']
    for vs in vsStats:
        vsName = vs['@name']
        cs_pkts_in = vs['clientside.pkts_in']
        cs_pkts_out = vs['clientside.pkts_out']
        cs_bytes_in = vs['clientside.bytes_in']
        cs_bytes_out = vs['clientside.bytes_out']
        cs_max_conns = vs['clientside.max_conns']
        cs_total_conns = vs['clientside.tot_conns']
        cs_curr_conns = vs['clientside.cur_conns']
        tot_reqs = vs['tot_requests']
        ss_pkts_ins = vs['serverside.pkts_in']
        ss_pkts_out = vs['serverside.pkts_out']
        ss_bytes_in = vs['serverside.bytes_in']
        ss_bytes_out = vs['serverside.bytes_out']
        ss_max_conns = vs['serverside.max_conns']
        ss_total_conns = vs['serverside.tot_conns']
        ss_curr_conns = vs['serverside.cur_conns']
        cursor.execute("insert into vs_stats_tbl ('vsName', 'cs_pkts_in', 'cs_pkts_out', 'cs_bytes_in', 'cs_bytes_out', 'cs_max_conns', 'cs_total_conns', 'cs_curr_conns', 'ss_pkts_in', 'ss_pkts_out', 'ss_bytes_in', 'ss_bytes_out', 'ss_max_conns', 'ss_total_conns', 'ss_curr_conns', 'tot_reqs' ) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (vsName, cs_pkts_in, cs_pkts_out, cs_bytes_in, cs_bytes_out, cs_max_conns, cs_total_conns, cs_curr_conns, ss_pkts_ins, ss_pkts_out, ss_bytes_in, ss_bytes_out, ss_max_conns, ss_total_conns,ss_curr_conns, tot_reqs))
        conn.commit()
        

############################## retrieveObectCounts ########################################
def retrieveObectCounts(conn):

    vsCountQuery = "select count(*) from vs_tbl"
    poolCountQuery = "select count(*) from pool_tbl"
    poolMembersCountQuery = "select count(*) from member_tbl"
    iRulesCountQuery = "select count(*) from irules_tbl"
    clientSslCountQuery = "select count(*) from clientssl_tbl "
    serverSslCountQuery = "select count(*) from serverssl_tbl "
    httpCountQuery = "select count(*) from http_tbl "
    tcpCountQuery = "select count(*) from tcp_tbl"
    monitorCountHttpQuery = "select count(*) from monitor_tbl where monitorType = 'http' "
    monitorCountHttpsQuery = "select count(*) from monitor_tbl where monitorType = 'https' "
    monitorCountTcpQuery = "select count(*) from monitor_tbl where monitorType = 'tcp' "
    
    resp = conn.execute(vsCountQuery)
    vsCount = resp.fetchone()[0]

    resp = conn.execute(poolCountQuery)
    poolCount = resp.fetchone()

    resp = conn.execute(poolMembersCountQuery)
    poolMemberCount = resp.fetchone()

    resp = conn.execute(iRulesCountQuery)
    iRulesCount = resp.fetchone()

    resp = conn.execute(clientSslCountQuery)
    clientSSLCount = resp.fetchone()[0]  

    resp = conn.execute(serverSslCountQuery)
    serverSSLCount = resp.fetchone()[0]  

    resp = conn.execute(httpCountQuery)
    httpCount = resp.fetchone()[0]

    resp = conn.execute(tcpCountQuery)
    tcpCount = resp.fetchone()[0]

    resp = conn.execute(monitorCountHttpQuery)
    monitorHttpCount = resp.fetchone()[0]

    resp = conn.execute(monitorCountHttpsQuery)
    monitorHttpsCount = resp.fetchone()[0]  

    resp = conn.execute(monitorCountTcpQuery)
    monitorTcpCount = resp.fetchone()[0]    

    return vsCount, poolCount, poolMemberCount,iRulesCount, clientSSLCount, serverSSLCount, httpCount, tcpCount, monitorHttpCount, monitorHttpsCount, monitorTcpCount

############################## retrieveVirtualInfo ########################################
def retrieveVirtualInfo(conn, cName, hName):
    
    udpVsQuery      = "select count(*) from vs_tbl where ipProtocol = 'udp' "
    anyVsQuery      = "select count(*) from vs_tbl where ipProtocol = 'any' "
    tcpVsQuery      = "select count(*) from vs_tbl where ipProtocol = 'tcp' "
    apmVsQuery      = "select count(*) from vs_tbl where apmEnabled = 'true' "
    wafVsQuery      = "select count(*) from vs_tbl where wafEnabled = 'true' "
    vsNoiRulesQuery = "select count(*) from vs_tbl where ruleCount = 0 "
    vsSingleRuleQuery = "select count(*) from vs_tbl where ruleCount = 1  "
    vsMultiRuleQuery = "select count(*) from vs_tbl where ruleCount > 1 "    

    resp = conn.execute(udpVsQuery)
    udpVsCount =resp.fetchone()[0]

    resp = conn.execute(anyVsQuery)
    anyVsCount = resp.fetchone()[0]

    resp = conn.execute(tcpVsQuery)
    tcpVsCount = resp.fetchone()[0]

    resp = conn.execute(apmVsQuery)
    apmVsCount = resp.fetchone()[0]

    resp = conn.execute(wafVsQuery)
    wafVsCount = resp.fetchone()[0]

    resp = conn.execute(vsNoiRulesQuery)
    vsNoRuleCount = resp.fetchone()[0]

    resp = conn.execute(vsSingleRuleQuery)
    vsSingleRuleCount = resp.fetchone()[0]

    resp = conn.execute(vsMultiRuleQuery)
    vsMultiRuleCount = resp.fetchone()[0]

    lst = [[ 'Any', anyVsCount], ['UDP', udpVsCount], ['TCP', tcpVsCount], ['APM', apmVsCount], ['WAF', wafVsCount]]
    vsTypeDf = pd.DataFrame(lst, columns =['Type','Count'])
    fig=px.pie(vsTypeDf, values='Count', names='Type', title='Virtual Servers by Type')    
    fig.write_image('/app/static/images/' + 'vsTypes-pie-' +cName + '-' + hName + '.png')
    
 
    ruleList = [['No iRules', vsNoRuleCount], ['Single iRule', vsSingleRuleCount], ['Multi-iRule', vsMultiRuleCount]]
    vsRuleDf = pd.DataFrame(ruleList, columns = ['Type', 'Count'])
    fig = px.bar(vsRuleDf, x='Type', y='Count', title = 'Count of Virtual Servers using iRules')
    fig.write_image('/app/static/images/vsRules-bar-' + cName + '-' + hName + '.png')




    return udpVsCount, anyVsCount, tcpVsCount, apmVsCount, wafVsCount, vsNoRuleCount, vsSingleRuleCount, vsMultiRuleCount


############################## xcConfIssues ########################################
def xcConfIssues(conn):
    unSupportedHealthCheckTypesQuery = "select vs_tbl.vsName, pool_tbl.poolName, monitor_tbl.monitorName, monitor_tbl.monitorType from vs_tbl inner join pool_tbl on vs_tbl.poolName = pool_tbl.poolName inner join monitor_tbl on pool_tbl.monitorName = monitor_tbl.monitorName where monitor_tbl.monitorType != 'tcp' and monitor_tbl.monitorType not like '%http%' "
    unSupportedPersistTypeQuery  = "select vs_tbl.vsName, vs_tbl.persistName, persist_tbl.persistType from vs_tbl inner join persist_tbl on vs_tbl.persistName = persist_tbl.persistName where persist_tbl.persistType != 'cookie' and persist_tbl.persistType != 'source-addr' "
    unSupportedFallbackPersistQuery = "select vsName, persistName, fallbackPersistName from vs_tbl where fallbackPersistName != 'none' "
    resp = conn.execute(unSupportedHealthCheckTypesQuery)
    uhtqList = resp.fetchall()

    resp = conn.execute(unSupportedPersistTypeQuery)
    upList = resp.fetchall()

    resp = conn.execute(unSupportedFallbackPersistQuery)
    uFallPersistList = resp.fetchall()

    return uhtqList, upList, uFallPersistList



############################## initDB ########################################

def initDb(conn):
  cursor = conn.cursor()

  cursor.execute("CREATE TABLE pool_tbl ( id integer primary key AUTOINCREMENT, poolName TEXT,	poolDescription TEXT,	lbMethod TEXT, 	monitorName TEXT,	slowRamp INTEGER)")
  
  cursor.execute("CREATE TABLE member_tbl (id integer primary key AUTOINCREMENT, poolName text, memberName text, memberPort text, memberAddress text, sessionState text, availabilityState text  ) ")

  cursor.execute("CREATE TABLE clientssl_tbl (id integer primary key AUTOINCREMENT, clientsslName TEXT, certName TEXT,	chainName TEXT, cipher TEXT,	 keyName TEXT, serverName TEXT)")

  cursor.execute("CREATE TABLE serverssl_tbl (id integer primary key AUTOINCREMENT, serverSSLName TEXT, certName TEXT, chainName TEXT, cipher  TEXT, keyName TEXT,	peerCertMode TEXT)")

  cursor.execute("CREATE TABLE http_tbl (id integer primary key AUTOINCREMENT, httpName TEXT, headerErase TEXT, headerInsert TEXT, insertXFF TEXT)")

  cursor.execute("CREATE TABLE tcp_tbl (id integer primary key AUTOINCREMENT, tcpName TEXT, idleTimeout INTEGER)")

  cursor.execute("CREATE TABLE vs_tbl (id integer primary key AUTOINCREMENT, vsName TEXT, vsAddr TEXT, vsPort INTEGER,  description TEXT, ipProtocol TEXT, persistName TEXT, trafficPolicy TEXT,	poolName TEXT, apmEnabled TEXT, wafEnabled TEXT, ruleCount Integer, snatPool TEXT, snatType TEXT, fallbackPersistName text )")

  cursor.execute("create table profile_tbl (id integer primary key,  profileName text unique, profileType text)")

  cursor.execute("create table vs_profile_tbl (id integer primary key,  vsName text, profileName text, profileContext text )")

  cursor.execute("CREATE TABLE irules_tbl (id integer primary key AUTOINCREMENT, ruleName TEXT, ruleDefinition TEXT, ruleLength integer)")
  
  cursor.execute("CREATE TABLE monitor_tbl (id integer primary key AUTOINCREMENT, monitorName TEXT, monitorType TEXT, monitorCert TEXT, monitorCipher TEXT, interval integer, monitorKey TEXT, receiveString TEXT, sendString TEXT, timeout integer )")

  cursor.execute("CREATE TABLE pool_monitor_tbl (id integer primary key AUTOINCREMENT,  poolName TEXT, monitorName TEXT   )")

  cursor.execute("CREATE TABLE qkview_tbl (id integer primary key AUTOINCREMENT, hostName TEXT, qkviewDate TEXT, serialNumber TEXT, entitlementDate TEXT, firmwareVersion TEXT, qkviewNumber integer, uptimeStr text)")

  cursor.execute("create table persist_tbl (id integer primary key,  persistName text unique, persistType text, alwaySend text, cookieName text, cookieExpiration text, cookieEncryption text, cookieHttpOnly text, cookieMethod text, cookieSecure text, hashAlgorithm text, mask text, matchAcrossPools text ,matchAcrossServices text, matchAcrossVirtuals text , mirror text, overrideConnectionLimit text, timeout integer)")
 
  cursor.execute("CREATE TABLE graphs_tbl (id integer primary key AUTOINCREMENT, graphName TEXT, graphImage TEXT)")
 
  cursor.execute("create table vs_irule_tbl (id integer primary key autoincrement, vsName text, ruleName text)")
  cursor.execute("create table vs_stats_tbl (id integer primary key AUTOINCREMENT, vsName text, cs_pkts_in integer, cs_pkts_out integer, cs_bytes_in integer, cs_bytes_out integer, cs_max_conns integer, cs_curr_conns integer, cs_total_conns integer, ss_pkts_in integer, ss_pkts_out integer, ss_bytes_in integer, ss_bytes_out integer, ss_max_conns integer, ss_curr_conns integer, ss_total_conns integer, tot_reqs integer )")
 
  cursor.execute("insert into monitor_tbl ('monitorName', 'monitorType', 'interval', 'timeout') values ('/Common/gateway_icmp', 'gateway-icmp', 5, 16)")
  cursor.execute("insert into monitor_tbl ('monitorName', 'monitorType', 'interval', 'timeout') values ('/Common/icmp', 'icmp', 5,16)")

  cursor.execute("insert into persist_tbl ('persistName', 'persistType', 'mirror', 'timeout') values (?,?,?,?)", ( '/Common/dest_addr', 'dest-addr', 'disabled', 180 ))
  cursor.execute("insert into persist_tbl ('persistName', 'persistType', 'mirror', 'timeout') values (?,?,?,?)", ( '/Common/hash', 'hash', 'disabled', 180 ))
  cursor.execute("insert into persist_tbl ('persistName', 'persistType', 'mirror', 'timeout') values (?,?,?,?)", ( '/Common/msrdp', 'msrdp', 'disabled', 180 ))
  cursor.execute("insert into persist_tbl ('persistName', 'persistType', 'mirror', 'timeout') values (?,?,?,?)", ( '/Common/sip_info','sip', 'disabled', 180 ))
  cursor.execute("insert into persist_tbl ('persistName', 'persistType', 'mirror', 'timeout') values (?,?,?,?)", ( '/Common/source_addr', 'source-addr', 'disabled', 180 ))
  cursor.execute("insert into persist_tbl ('persistName', 'persistType', 'mirror', 'timeout') values (?,?,?,?)", ( '/Common/ssl', 'ssl', 'disabled', 180 ))
  cursor.execute("insert into persist_tbl ('persistName', 'persistType', 'mirror', 'timeout') values (?,?,?,?)", ( '/Common/universal', 'universal', 'disabled', 180 ))
  conn.commit()

###################################           ##################################

@app.route('/', methods=['GET'])
def home():
    doc = dominate.document(title='Appscan via Qkview')
    with doc.head:
        link(rel='stylesheet', href='/css/style.css')
    with doc:
        with div(cls='header'):
            h3('Appview')
        with div(cls='body'):
            p('Appview is a Python based application that will take an F5 Qkview file and parse write them to a SQLite database file.')
            ol()
            li('Monitors - monitor_tbl')
            li('Pools - pool_tbl')
            li('Pool Members - member_tbl')
            li('Persistence Profiles - persist_tbl')
            li('TCP Profiles - tcp_tbl')
            li('ClientSSL - clientssl_tbl')
            li('ServerSSL - serverssl_tbl')
            li('HTTP Profiles - http_tbl ')
            li('iRules - irules_tbl')
            li('Virtual Servers - vs_tbl')
            li('virtual to iRule table - vs_irule_tbl')
            li('graphs - graphs_tbl')
            br()
            br()

            with div(cls='form'):
                with form(method='GET', name='appscan', action='/qkview'): 
                    label('Parse Qkview'),input_(type='radio', value='parse', name='action') 
                    br()
                    label('Review Qkview'),input_(type='radio', value='review', name='action')
                    br()   
                    input_(type='submit', value='Submit')
                

    return doc.render()
                 

@app.route('/qkview', methods=['GET'])
def qkview():
    actionType = request.args.get('action')
    if actionType == 'parse':
      doc = dominate.document(title='Application View via Qkview')
      with doc.head:
          link(rel='stylesheet', href='style.css')
      with doc:
          with a(href='/'):
              p('Home')          
          with div(cls='header'):
              h3('Appview')
          with div(cls='body'):
              with form(method='POST', name='qkv_parse', action='/qkview_parse'):
                with table(cls='parse'):
                    l = tr(th('Customer: '),td(input_(type='text', name='cust_name', size=20)))
                    l.add(tr(th('Qkview Number: '), td(input_(type='text', name='qkv_num', size=15))))
                    l.add(tr(th('oAuth_Client:  '), td(input_(type='text', name='oauth_client', size=30))))     
                    l.add(tr(th('oAuth Secret: '), td(input_(type='text', name='oauth_secret', size=50))))
                    l.add(tr(td(input_(type='submit', value='Submit', colspan=2))))
    else:
      doc = dominate.document(title='Application View via Qkview')
      with doc.head:
          link(rel='stylesheet', href='/css/style.css')
      with doc:
          with a(href='/'):
              p('Home')          
          with div(cls='header'):
              h3('Appview')
          with div(cls='body'):
            dirlist = pathlib.Path('/app/qkview_output')
            filelist = dirlist.rglob('*.db')

            with div(cls='form'):
                with form(method='POST', name='dbFile', action='/qkview_review'): 
                    label('Select customer and qkview hostname from the dropdown list')
                    with select(name='dbfile'):
                        for file in filelist:
                          fileStr = str(file)
                          fields = fileStr.split('/')
                          fileName = fields[3] + ' - ' + fields[4][:-3]
                          with option(value=str(fileStr)):
                            label(fileName)
                    input_(type='hidden', name='cust_name', value=fields[3])
                    input_(type='hidden', name='host_name', value=fields[4][:-3])
                    input_(type='submit', value='Submit')
            
    return doc.render()

@app.route('/qkview_parse', methods=['POST'])
def qkview_parse():

   custName = request.form['cust_name']
   qkviewNum = request.form['qkv_num']
   oauth_client = request.form['oauth_client']
   oauth_secret = request.form['oauth_secret']
   path = '/app/qkview_output/' + custName
   
   if not os.path.exists(path):
     os.makedirs(path)

   bearer_token = request_bearer_token(oauth_client, oauth_secret)
   headers = {
     'Authorization': 'Bearer ' + bearer_token ,
     'Accept': 'application/vnd.f5.ihealth.api.v1.0',
     'User-Agent': 'F5SE'
   }   
   # retrieve hostname and chassis serial number
   url = baseIhealthApiURL + str(qkviewNum)
   response = requests.request("GET", url,  headers=headers)
   if response.status_code != 200:
     print('Qkview ' + qkviewNum + ' is unavailable, please login to iHealth to verify status of qkview.  Exiting ...' )
     sys.exit()

   dictOut = xmltodict.parse(response.text)
   chassis_serial = dictOut['qkview']['chassis_serial']
   hostName = dictOut['qkview']['hostname']
   if 'entitlement' in dictOut['qkview']:
      entitlement_date = dictOut['qkview']['entitlement']['expiration_date']
   else: 
      entitlement_date = 'Unavailable'
   gDate = dictOut['qkview']['generation_date'] 
   gDate2 = int(gDate) / 1000.0
   qkviewDate = datetime.datetime.fromtimestamp(gDate2).strftime("%Y-%m-%d %H:%M:%S")
   dbFile = path + '/' + hostName + '.db'
   if os.path.exists(dbFile):
      os.remove(dbFile)
   connection = sqlite3.connect(dbFile)
   cursor = connection.cursor()
   initDb(connection)
     
   # Retrieve running version
   url = baseIhealthApiURL + str(qkviewNum) + "/commands/3af0d910d98f07b78ac322a07920c1c72b5dfc85"
   response = requests.request("GET", url,  headers=headers)
   if response.status_code == 200:
    dictOut = xmltodict.parse(response.text)
    encoded = dictOut['commands']['command']['output'] 
    if len(encoded) % 4 == 3:
      encoded += '='
    elif len(encoded) % 4 == 2:
      encoded += '=='
       
    decoded_cmdOut = base64.b64decode(encoded).decode(encoding='UTF-8').split('\n')
    for line in decoded_cmdOut:
       fields = line.split(' ')
       if len(fields) > 1:
         if fields[2] == 'yes':
           firmware_version = fields[7]
       
       # Insert qkview info into qkview_tbl 
    cursor.execute("insert into qkview_tbl ('hostName', 'qkviewDate', 'serialNumber', 'entitlementDate', 'firmwareVersion', 'qkviewNumber') values (?,?,?,?,?,?)", (hostName, qkviewDate, chassis_serial, entitlement_date, firmware_version, qkviewNum))
    connection.commit()
  

    for cmd in cmdDict:
        cmdId = str(cmdDict[cmd])
        url = baseIhealthApiURL + str(qkviewNum) + "/commands/" + cmdId
        response = requests.request("GET", url, headers=headers)
        if response.status_code == 200:
          file = decodeQkviewCommands(response.text)
          if 'rules' in cmd:
            lines = file.split('ltm rule ')
          else:
            lines = file.splitlines(keepends=True)
          if 'list pools' in cmd:
            parsePools(connection,lines)
          elif 'list rules' in cmd:
             parseRules(connection, lines) 
          elif 'list virtuals' in cmd:
            parseVirtuals(connection,lines)
          elif 'list clientssl' in cmd:
            parseClientSSL(connection,lines)
          elif 'list http' in cmd:
            parseHTTP(connection, lines)
          elif 'list serverSSL' in cmd:
            parseServerSSL(connection, lines)
          elif 'list tcp' in cmd:
            parseTCP(connection, lines)
          elif 'list mon ' in cmd:
            parseMonitors(connection, lines)

    # retrieve bigip.conf to parse for monitors and persistence profiles
    print('Retrieving bigip.conf ')
    url = baseIhealthApiURL + str(qkviewNum) + '/files/Y29uZmlnL2JpZ2lwLmNvbmY' 
    response =  requests.request("GET", url, headers=headers)
    if response.status_code == 200:
      parseBigIpConf(connection, response.text.splitlines(keepends=True))
    
    # retrieve and parse the stat_module.xml               
    url =  baseIhealthApiURL + str(qkviewNum) + '/files/c3RhdF9tb2R1bGUueG1s'
    response =  requests.request("GET", url, headers=headers)
    if response.status_code == 200:
        parseStats(connection, response.text) 

    # retrieve and parse the avr_module.xml
    url = baseIhealthApiURL + str(qkviewNum) + '/files/YXZyX21vZHVsZS54bWw'
    response = requests.request("GET", url, headers=headers)
    if response.status_code == 200:
       dict = xmltodict.parse(response.text)
       upDateStr = dict['Qkproc']['mysql_data']['query_result'][3]['row'][0]['CREATE_TIME']
       #sys.stdout.write(upDateStr)
       connection.execute('update qkview_tbl set uptimeStr = ? where id = ? ', (upDateStr, 1))
       connection.commit()
        

   doc = dominate.document(title='Application View via Qkview')
   with doc.head:
       link(rel='stylesheet', href='style.css')
   with doc:
       tags.meta(http_equiv="refresh", content="15; URL=/qkview?action=review")
       with div(cls='header'):
          with a(href='/'):
            p('Home') 
          h3('Appview')
       with div(cls='body'):
           p('Customer: ' + custName)
           p('Qkview ID: ' + qkviewNum)
           p('oAuth Client: ' + oauth_client)
           p('oAuth Secret: ' + oauth_secret)

   return doc.render() 


@app.route('/qkview_review', methods=['POST'])
def qkv_review():
    custName = request.form['cust_name']
    hostName = request.form['host_name']
    dbFile = request.form['dbfile']

    if not os.path.exists(dbFile):
        doc = dominate.document(title='Error')
        with doc:
            h1('Error! - DB file:' + dbFile + ' is not found,')
        return doc.render()
    else:
        conn = sqlite3.Connection(dbFile)
        #generateVsTypeGraph(custName, hostName)

        qkvQuery = conn.execute("select * from qkview_tbl")
        (id, hostName, qkviewDate, serialNumber, servicesDate, firmwareVersion, qkviewNumber, uptimeStr) = qkvQuery.fetchone()

        ruleLengthQuery = "select ruleName, ruleDefinition, ruleLength from irules_tbl where ruleLength < 20 order by ruleLength"
        rlq = conn.execute(ruleLengthQuery)
        rlqList = rlq.fetchall()

        supportedVsQuery = "select vsName, ipProtocol, persistName, trafficPolicy, ruleCount  from vs_tbl where ipProtocol in ('udp','tcp') and ruleCount = 0 and trafficPolicy = 'none' and apmEnabled = false"
        resp = conn.execute(supportedVsQuery)
        vsList = resp.fetchall()
        
        # query for virtuals with single irule which is less than 20 lines long
        vs1ruleless20lines = "select vs_tbl.vsName, vs_tbl.ruleCount, vs_irule_tbl.ruleName, irules_tbl.ruleLength  from vs_tbl inner join vs_irule_tbl on vs_tbl.vsName = vs_irule_tbl.vsName inner join irules_tbl on vs_irule_tbl.ruleName = irules_tbl.ruleName where vs_tbl.ruleCount = 1 and irules_tbl.ruleLength < 20"
        resp = conn.execute(vs1ruleless20lines)
        vs1Rule20linesList = resp.fetchall()

        (vsCount, poolCount, poolMemberCount, iRulesCount, clientSSLCount, ServerSSLCount, httpCount, tcpCount, monitorHTTPCount, monitorHTTPSCount, monitorTCPCount) = retrieveObectCounts(conn)

        (udpVsCount, anyVsCount, tcpVsCount, apmVsCount, wafVsCount, vsNoRuleCount, vsSingleRuleCount, vsMultiRuleCount) = retrieveVirtualInfo(conn, custName, hostName)
        vs_w_health_list, vs_w_persist_list, vs_fall_persist_list = xcConfIssues(conn)

        ce_sizing_query = "select vsName, cs_pkts_out, cs_bytes_out, tot_reqs, cs_curr_conns, cs_max_conns, cs_total_conns from vs_stats_tbl order by cs_bytes_out"
        resp = conn.execute(ce_sizing_query)
        ceSizeList = resp.fetchall()
        generate_uptime_query = "select qkviewDate, uptimeStr from qkview_tbl"
        resp = conn.execute(generate_uptime_query)
        upQueryLst = resp.fetchall()

        for gDate,uDate in upQueryLst:
           genDate = datetime.datetime.strptime(gDate, "%Y-%m-%d %H:%M:%S")
           upDate = datetime.datetime.strptime(uDate,  "%Y-%m-%d %H:%M:%S")
        upDelta = genDate - upDate
        upDays = int(upDelta.total_seconds()/86400)
        upMonths = round(upDays / 30)



        doc = dominate.document(title='BIG-IP Qkview Summary')
        with doc.head:
            link(rel='stylesheet', href='/css/style.css')

        with doc:
            with div(cls = 'content'):
                with p(cls='header'):
                    with a(href='/'):
                       p('Home')
                with table(cls='modern-table', id='qkview_info'):
                    l = tr(th('Host Name:'), td(hostName))
                    l.add(tr(th('Qkview Generation Date:'), td(qkviewDate)))
                    l.add(tr(th('Serial Number:'), td(serialNumber)))
                    l.add(tr(th('Services End Date:'), td(servicesDate)))
                    l.add(tr(th('Uptime:'), td(uptimeStr)))
                    l.add(tr(th('Software Version'), td(firmwareVersion)))
                    l.add(tr(th('Qkview Number'), td(a(qkviewNumber, href='https://ihealth2.f5.com/qkview-analyzer/qv/'+ str(qkviewNumber)))))
                br() 

            with div(): 
                with table(cls='modern-table', id='object_counts'):
                    l = thead(th('Object Counts', colspan=2))
                    l.add(tr(th('Virtuals'), td(vsCount)))
                    l.add(tr(th('Pools '), td(poolCount)))
                    l.add(tr(th('Pool Members'), td(poolMemberCount)))
                    l.add(tr(th('iRules'), td(iRulesCount)))
                    l.add(tr(th('Client-SSL'), td(clientSSLCount)))
                    l.add(tr(th('Server-SSL'), td(ServerSSLCount)))
                    l.add(tr(th('HTTP'), td(httpCount)))
                    l.add(tr(th('TCP'), td(tcpCount)))
                    l.add(tr(th('Monitor HTTP'), td(monitorHTTPCount)))
                    l.add(tr(th('Monitor HTTPS'), td(monitorHTTPSCount)))
                    l.add(tr(th('Monitor TCP'), td(monitorTCPCount)))
                br()
            with div():
                br()
                img(src='/images/vsTypes-pie-' +custName + '-' + hostName + '.png', cls='img_class')
                br()
                img(src='/images/vsRules-bar-' + custName + '-' + hostName + '.png', cls='img_class')
                br()

            with div():
#                with table(cls='table', id='iRulesUnder20lines'):
#                    tr(th('iRules under 20 lines', colspan=3))
#                    tr(td('Rule Name'), td('Rule Definition'), td('Rule Length'))
#                    for rName,rDef, rLength in rlqList:
#                        tr(td(rName), td(code(rDef)),td(rLength))
#                    br()

                with table(cls='table', id='ce_sizing_by_vs'):
                   with thead():
                      tr(th('CE Sizing by Virtual server', colspan=9))
                      tr(td('VS Name'), td('Pkts Out'), td('Bytes Out'), td('Monthly Bytes'), td('Total Requests'), td('Monthly Requests'), td('Current Conns'), td('Max Conns'), td('Total Conns'))
                   for vsName, pkts_out, bytes_out, total_reqs, curr_conns, max_conns, total_conns in ceSizeList:
                      monthly_bytes = round(bytes_out / upMonths)
                      monthly_reqs = round(total_reqs / upMonths)
                      tr(td(vsName), td(pkts_out), td(bytes_out), td(monthly_bytes), td(total_reqs), td(monthly_reqs), td(curr_conns), td(max_conns), td(total_conns))
                   br()
                   br()

#                with table(cls='table', id='xc_vs_table'):
#                    tr(th('Virtual Servers possible XC candidates', colspan=7))
#                    tr(td('VS Name'), td('IP Protocol'), td('Persist Name'),td('Traffic Policy'), td('iRule Count'), td('iRuleName'), td('Rule Length') )
#                    for vName,ipProto, persName, trafficPolicy, ruleCount in vsList:
#                        tr(td(vName), td(ipProto),td(persName), td(trafficPolicy), td(ruleCount), td(), td() )
#                    for vsName, rCount, ruleName, ruleLength in vs1Rule20linesList:
#                        tr(td(vsName),td(), td(), td(),td(rCount), td(ruleName), td(ruleLength) )
#                    br()

            if len(vs_w_health_list) > 0:
                with div():
                    with table(cls='table', id='xcHealthcheckIssues'):
                        tr(th('Virtual Servers using UnSupported Health Monitor Types', colspan=4))
                        tr(th('VS Name'), th('Pool Name'), th('Monitor Name'), th('Monitor Type'))
                        for (vsName, poolName, monitorName, monitorType) in vs_w_health_list:
                            tr(td(vsName), td(poolName), td(monitorName), td(monitorType))
                        br()
            
            if len(vs_w_persist_list) > 0:
                with div():
                    with table(cls='table', id='xcPersistTypeIssues'):
                        tr(th('Virtual Servers usig UnSupported Persistence Types', colspan=3))
                        tr(th('VS Name'), th('Persist Name'), th('Persist Type'))
                        for (vsName, persistName, persistType) in vs_w_persist_list:
                            tr(td(vsName), td(persistName), td(persistType))
                    br()
            if len(vs_fall_persist_list) > 0:
                with div():
                    with table(cls='table', id='xcFallbackPersistIssues'):
                        tr(th('Virtual Servers usig UnSupported Fallback Persistence', colspan=3))
                        tr(th('VS Name'), th('Persist Name'), th('Fallback Persist Name'))
                        for (vsName, persistName, fallPersistName) in vs_fall_persist_list:
                            tr(td(vsName), td(persistName), td(fallPersistName))
                    
    return doc.render()


@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    doc = dominate.document(title='Application View via Qkview')
    with doc.head:
        link(rel='stylesheet', href='style.css')
    with doc:
        p('Server is up')

    return doc.render()

######################## main ########################################
# variables 

cmdDict = {
  'list pools':     '10c2c9c206c41dcbd6a081ac517aa3e52e2a7741',
  'list clientSSL': '644d821949e8f1aa984104abc9a752b32681118a',
  'list http':      '8312f21972c9351ef8e1f309aa514a2729c9cdb6',
  'list serverSSL': 'defe909cc1a15a72216d8ec124b5a0a64c10b381',
  'list tcp':       '03051e4e2e257f0756d57c3c167ef8669cf7dccd',
  'list mon http':  '2888b5db127fb5839958620845fe041b7b743634',
  'list mon https': '4bac75fe973102f59c8485b234c49e558a5a26f8',
  'list mon tcp':   '515991d0283ecf40d96567cebe22c7f8fef2be80',
  'list virtuals':  'a11a885a65838bd6f3fc0e8d1ac2e554c1d50a1a',
  'list rules':     '8b85e073cc3dcf303db34025e931a5286f26ce77',  
}

dictGraphs = {
  'active_connections': 'activecons',
  'by_core_cpu': 'blade0cpucores',
  'system_CPU': 'CPU',
  'cpu_plane': 'detailplanestat',
  'memory_breakdown': 'memorybreakdown',
  'new_connections': 'newcons',
  'throughput': 'throughput'
}

baseIhealthApiURL = "https://ihealth2-api.f5.com/qkview-analyzer/api/qkviews/" 

TCP_Profiles={}
clientSSL_Profiles = {}
serverSSL_Profiles = {}
HTTP_Profiles = {}
rulesInUse={}


# Run Server
if __name__ == '__main__':
  app.run(debug=False, host='0.0.0.0')

