
from OTXv2 import OTXv2
from pandas.io.json import json_normalize
from datetime import datetime, timedelta
import requests
from pymisp import PyMISP
import time

# service parameters
otx_key = 'XXXXXXXXXXXX'
misp_url = 'http://misp.tld'
misp_key = 'NNNNNNNNNNNN'

def saveTimestamp(timestamp=None):
        mtimestamp = timestamp
        if not timestamp:
                mtimestamp = datetime.now().isoformat()

        fname = "timestamp"
        f = open(fname, "w")
        f.write(mtimestamp)
        f.close()

def readTimestamp():
        fname = "timestamp"
        f = open(fname, "r")
        mtimestamp = f.read()
        f.close()
        return mtimestamp

def pulse_to_misp(misp, pulse):
    """
        Given a MISP context and a pulse containing indicators, use this information to
        - create a new MISP event using this context and metadata from the pulse object
        - populate attributes of this event that are derived from the indicators contained within the pulse
    """
    # create the event
    pulse_name = pulse['author_name'] + ' | ' + pulse['name']
    pulse_date = pulse['modified']
    dt = datetime.strptime(pulse_date, '%Y-%m-%dT%H:%M:%S.%f')
    event = misp.new_event(0,4,2,pulse_name, date=dt.strftime('%Y-%m-%d'), published=True)

    time.sleep(0.2)

    # populate the attributes
    for ind in pulse['indicators']:
        ind_type = ind['type']
        ind_val = ind['indicator']
        """
        u'FileHash-SHA256',
        u'domain',
        u'URL',
        u'hostname',
        u'URI',
        u'email',
        u'FileHash-SHA1',
        u'Mutex',
        u'IPv4',
        u'FileHash-MD5']
        """
        if ind_type == 'FileHash-SHA256':
            misp.add_hashes(event, sha256=ind_val)

        elif ind_type == 'FileHash-SHA1':
            misp.add_hashes(event, sha1=ind_val)

        elif ind_type == 'FileHash-MD5':
            misp.add_hashes(event, md5=ind_val)

        elif ind_type == 'URI' or ind_type == 'URL':
            misp.add_url(event, ind_val)

        elif ind_type == 'domain':
            misp.add_domain(event, ind_val)

        elif ind_type == 'hostname':
            misp.add_hostname(event, ind_val)

        elif ind_type == 'IPv4' or ind_type == 'IPv6':
            misp.add_ipdst(event, ind_val)

        elif ind_type == 'email':
            misp.add_email_src(event, ind_val)

        elif ind_type == 'Mutex':
            misp.add_mutex(event, ind_val)

        else:
            print("Unsupported indicator type: %s" % ind_type)

        time.sleep(0.2)

if __name__ == "__main__":

    otx = OTXv2(otx_key)

    # The getall() method downloads all the OTX pulses and their assocciated indicators of compromise (IOCs) from your account. 
    # This includes all of the following:  
    # - OTX pulses to which you subscribed through the web UI
    # - Pulses created by OTX users to whom you subscribe
    # - OTX pulses you created. 
    # If this is the first time you are using your account, the download includes all pulses created by AlienVault. 
    # All users are subscribed to these by default.

    mtime = readTimestamp()
    pulses = otx.getsince(mtime)
    print("Retrived %d pulses" % len(pulses))

    # Create a connection to a MISP server where arguments are:
    #  - MISP URL
    #  - Key for user who can create and update events

    misp = PyMISP(misp_url, misp_key, False, 'json')

    # Summary of information retrieved from OTX
    for p in pulses:
        print(p['modified'])
        print(p['name'])
        print(p['author_name'])
        print(len(p['indicators']))
        print('='*12)

    # Add retrieved indicators (pulses) to MISP
    for pulse in pulses:
        pulse_to_misp(misp,pulse)

    saveTimestamp()
