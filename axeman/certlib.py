import base64
import math

import datetime
from collections import OrderedDict

from OpenSSL import crypto

import urllib.request
import urllib.parse
import json
import logging
import requests
import queue
from collections import deque

CTL_LISTS = 'https://www.gstatic.com/ct/log_list/log_list.json'

CTL_INFO = "https://{}/ct/v1/get-sth"

DOWNLOAD = "https://{}/ct/v1/get-entries?start={}&end={}"

from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, this, GreedyBytes, GreedyRange, Terminated, Embedded

MerkleTreeHeader = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / GreedyBytes
)

Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)

PreCertEntry = Struct(
    "LeafCert" / Certificate,
    Embedded(CertificateChain),
    Terminated
)


def retrieve_all_ctls(ses):
    with ses.get(CTL_LISTS, timeout=10) as response:
        ctl_lists = response.json()
        logs = ctl_lists['logs']
        for log in logs:
            log['disqualified'] = 'disqualified_at' in log
            if log['url'].endswith('/'):
                log['url'] = log['url'][:-1]
            owner = _get_owner(log, ctl_lists['operators'])
            log['operated_by'] = owner
        return logs


def get_max_block_size(log, ses):
    logging.info("Trying to get 10000 entries to determine block size")
    with ses.get(DOWNLOAD.format(log['url'], 0, 10000), timeout=10) as response:
        entries = response.json()
        return len(entries['entries'])


def retrieve_log_info(log, ses, get_block_size = True):
    block_size = -1
    if get_block_size:
        print("getting block sixze")
        block_size = get_max_block_size(log, ses)    
    try:
        with ses.get(CTL_INFO.format(log['url']), timeout=10) as response:
            info = response.json()
            info['block_size'] = block_size
            info.update(log)
            return info
    except ConnectionResetError:
        return {"tree_size": -1}
    except requests.exceptions.ConnectionError:
        return {"tree_size": -1}


def _get_owner(log, owners):
    owner_id = log['operated_by'][0]
    owner = next(x for x in owners if x['id'] == owner_id)
    return owner['name']


def populate_work(log):
    tree_size = log['tree_size']
    block_size = log['block_size']

    total_size = tree_size - 1
    start = log['start']
    end = start + block_size

    if end > tree_size:
        end = tree_size

    chunks = math.ceil((total_size - start) / block_size)

    if chunks == 0:
        raise Exception("No work needed!")
    logging.info("Populating chunk queue ... ({})".format(chunks))
    chunk_list = []
    for _ in range(chunks):
        # Cap the end to the last record in the DB
        if end >= tree_size:
            end = tree_size - 1

        assert end >= start, "End {} is less than start {}!".format(end, start)
        assert end < tree_size, "End {} is less than tree_size {}".format(end, tree_size)

        #logging.info("Chunk: {}-{}".format(start, end))
        chunk_list.append((start, end))
        start += block_size

        end = start + block_size + 1
    return deque(chunk_list)


def add_all_domains(cert_data):
    all_domains = []

    # Apparently we have certificates with null CNs....what?
    if cert_data['leaf_cert']['subject']['CN']:
        all_domains.append(cert_data['leaf_cert']['subject']['CN'])

    SAN = cert_data['leaf_cert']['extensions'].get('subjectAltName')

    if SAN:
        for entry in SAN.split(', '):
            if entry.startswith('DNS:'):
                all_domains.append(entry.replace('DNS:', ''))

    cert_data['leaf_cert']['all_domains'] = list(OrderedDict.fromkeys(all_domains))

    return cert_data


def dump_cert(certificate):
    subject = certificate.get_subject()

    try:
        not_before = datetime.datetime.strptime(certificate.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp()
    except:
        not_before = 0

    try:
        not_after = datetime.datetime.strptime(certificate.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp()
    except:
        not_after = 0

    return {
        "subject": {
            "aggregated": repr(certificate.get_subject())[18:-2],
            "C": subject.C,
            "ST": subject.ST,
            "L": subject.L,
            "O": subject.O,
            "OU": subject.OU,
            "CN": subject.CN
        },
        "extensions": dump_extensions(certificate),
        #"not_before": not_before,
        #"not_after": not_after,
        #"as_der": base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)).decode('utf-8')
    }

def dump_extensions(certificate):
    extensions = {}
    for x in range(certificate.get_extension_count()):
        extension_name = ""
        try:
            extension_name = certificate.get_extension(x).get_short_name()

            if extension_name == b'UNDEF':
                continue

            extensions[extension_name.decode('latin-1')] = certificate.get_extension(x).__str__()
        except:
            try:
                extensions[extension_name.decode('latin-1')] = "NULL"
            except Exception as e:
                pass
    return extensions
