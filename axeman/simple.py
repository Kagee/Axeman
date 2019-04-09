#! /usr/bin/env python3.6
import argparse

import sys
# import math
import base64
import os
# import traceback
# import hashlib
import logging
import locale

import OpenSSL
import requests
from requests_toolbelt.adapters.source import SourceAddressAdapter
# import queue
# from collections import deque
import gzip
import time
import glob
import csv
import json
# import datetime
import netifaces
from OpenSSL import crypto

import certlib

locale.setlocale(locale.LC_ALL, 'en_US.UTF8')

LOG_FORMAT = '[%(levelname)s:%(name)s:%(funcName)s] %(asctime)s - %(message)s'
LOG_LEVEL = logging.DEBUG


def log_pretty_print(log, ses):
    time1 = time.time()
    log_info = certlib.retrieve_log_info(log, ses, False)
    time2 = time.time()
    log_info['_time_get_log_info'] = '%0.3f ms' % ((time2-time1)*1000.0)
    combine_log = {**log, **log_info}
    return combine_log


def logs_pretty_print(args):
    ses = requests.Session()
    logs = certlib.retrieve_all_ctls(ses)
    ls = []
    for log in logs:
        ls.append(log_pretty_print(log, ses))
    num_sort = sorted(ls, key=lambda k: k['tree_size'])
    for l in num_sort:
        folder = "*" if os.path.exists(glue_dir(args.output_dir, l['url'])) else "-"
        l['folder'] = folder
        print("{tree_size}\t{folder}\t{url}\t{disqualified}\t{_time_get_log_info}".format(**l))


def find_start(log_info, start):
    if start == 0:
        log_info['start'] = 0
        return log_info
    log_info['start'] = int(start / log_info['block_size'])*log_info['block_size']
    logging.info("Block aligning start {} to {}".format(start, log_info['start']))
    return log_info


def find_end(log_info, end):
    if end == -1:
        log_info['end'] = log_info['tree_size']
        logging.info("Setting end to tree size: {}".format(log_info['tree_size']))
        return log_info
    calc_end = (int(end / log_info['block_size'])+1)*log_info['block_size']
    log_info['end'] = min(calc_end, log_info['tree_size'])
    logging.info(f"Block aligning end {end} to {log_info['end']}")
    return log_info


def setup_file_logger(args):
    file_handler = logging.FileHandler(f"{args.storage_dir}/run.log")
    formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)


def setup_log_data(args, ses, get_block_size=True):
    logs = certlib.retrieve_all_ctls(ses)
    log = {}
    try:
        log = [x for x in logs if x['url'] == args.ctl_url][0]
    except IndexError:
        logging.error(f"Invalid CTL log URL: {args.ctl_url}")
        if not args.no_check:
            sys.exit(1)
        else:
            log['url'] = args.ctl_url
            # operator? other?

    log['storage_dir'] = args.storage_dir

    combined_logs = {**log, **certlib.retrieve_log_info(log, ses, get_block_size)}

    combined_logs = find_start(combined_logs, args.ctl_start)
    combined_logs = find_end(combined_logs, args.ctl_end)
    return combined_logs


def download_log(args):
    if not os.path.exists(args.storage_dir):
        os.makedirs(args.storage_dir)
    elif args.ctl_start == 0:
        logging.error("Storage directory exists, -s should be > 0")
        sys.exit(1)
    ses = requests.Session()
    if args.sip:
        saa = None
        for iface in netifaces.interfaces():
            for ip in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                if ip['addr'] == args.sip:
                    logging.info(f"Setting source IP to {args.sip}")
                    saa = SourceAddressAdapter(args.sip)
        if saa:
            ses.mount('http://', saa)
            ses.mount('https://', saa)
        else:
            logging.fatal(f"{args.sip} is not a valid source address")
            sys.exit(1)

    if not args.gua:
        ses.headers.update({'User-Agent': requests.utils.default_user_agent() + "/hildenae+ct@gmail.com"})
    ses.verify = not args.no_verify
    setup_file_logger(args)
    log = setup_log_data(args, ses)
    with open(os.path.join(log['storage_dir'], "metadata"), 'w') as f:
        json.dump(log, f)
    chunks = certlib.populate_work(log)
    while len(chunks) != 0:
        logging.info("{} chunks remaning".format(len(chunks)))
        chunk = chunks.popleft()
        start = chunk[0]
        end = chunk[1]
        if args.slp_time != 0:
            time.sleep(args.slp_time)

        for x in range(3):
            try:
                with ses.get(certlib.DOWNLOAD.format(log['url'], start, end), timeout=10) as response:
                    entry_list = response.json()
                    logging.debug("Retrieved blocks {}-{}...".format(start, end))
                    break
            except Exception as e:
                logging.error("Exception getting block {}-{}! {}".format(start, end, e))

        else:  # Notorious for else, if we didn't encounter a break our request failed 3 times D:
            logging.error("Failed to get block {}-{}, writing to fail.csv".format(start, end))
            with open(os.path.join(log['storage_dir'], "fail.csv"), 'a') as f:
                f.write("{}\n".format(
                       ",".join([log['url'], str(start), str(end)])
                       )
                )
            return
        try:
            for index, entry in zip(range(start, end + 1), entry_list['entries']):
                entry['cert_index'] = index
        except KeyError as k:
            logging.error(k)
            logging.error(entry_list)

        index_min = entry_list['entries'][0]['cert_index']
        index_max = -1
        data = []
        for entry in entry_list['entries']:
            if entry['cert_index'] < index_min:
                index_min = entry['cert_index']
            if entry['cert_index'] > index_max:
                index_max = entry['cert_index']
            mtl = certlib.MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))
            cert_data = {}
            if mtl.LogEntryType == "X509LogEntryType":
                cert_data['type'] = "X509LogEntry"
                try:
                    chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, certlib.Certificate.parse(mtl.Entry).CertData)]
                except OpenSSL.crypto.Error:
                    logging.error(f"Failed to parse {entry['cert_index']}, inserting fake, empty data")
                    data.append("{};{}".format(entry['cert_index'], ''))
                    continue
                extra_data = certlib.CertificateChain.parse(base64.b64decode(entry['extra_data']))
                for cert in extra_data.Chain:
                    try:
                        chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
                    except OpenSSL.crypto.Error:
                        logging.error(f"Failed to parse {entry['cert_index']}, inserting fake, empty data")
                        data.append("{};{}".format(entry['cert_index'], ''))
                        continue
            else:
                cert_data['type'] = "PreCertEntry"
                extra_data = certlib.PreCertEntry.parse(base64.b64decode(entry['extra_data']))
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]
                for cert in extra_data.Chain:
                    chain.append(
                        crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
                    )

            cert_data.update({
                "leaf_cert": certlib.dump_cert(chain[0]),
                "chain": [certlib.dump_cert(x) for x in chain[1:]]
            })

            certlib.add_all_domains(cert_data)
            # Remove newlines from all_domains: https://crt.sh/?id=282646337
            data.append("{};{}".format(entry['cert_index'],
                                       ' '.join(cert_data['leaf_cert']['all_domains']
                                                ).replace("\n", " ").replace("\r", " ").replace("\0", " ")))

        logging.info("from: {} to: {}".format(index_min, index_max))
        csv_file = os.path.join(log['storage_dir'], "{0:011d}-{1:011d}.csv.gz".format(index_min, index_max))
        csv_tmp_file = os.path.join(log['storage_dir'], "{0:011d}-{1:011d}.csv.gz.tmp".format(index_min, index_max))
        logging.info(csv_file)

        with gzip.open(csv_tmp_file, 'wb') as f:
            f.write("\n".join(data).encode("utf-8"))
        os.rename(csv_tmp_file, csv_file)


def glue_dir(path, url):
    return os.path.join(path, 
                        "".join(
                                [c for c in url.replace("/", ".") if c.isalpha() or c.isdigit() or c == '.']
                                ).rstrip()
                        )

def all_log_status(args):
    logging.getLogger().setLevel(logging.INFO)
    logging.debug(f"Looking for logs in {args.output_dir}")
    metafiles = sorted(glob.glob(os.path.join(args.output_dir, '*','metadata')))
    #print(metafiles)
    for metafile in metafiles:
        with open(metafile) as json_file:
            l = json.load(json_file)
            d = os.path.dirname(metafile)
            on_disk_chunks = len(glob.glob(os.path.join(d, '*.csv.gz')))
            calculated_chunks = int(l['tree_size']/l['block_size'])
            percent_chunks = on_disk_chunks/calculated_chunks
            ses = requests.Session()
            ses.verify = False

            # Silence some stuff
            logging.getLogger().setLevel(logging.INFO)
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

            # update log tree size, but assume block size does not change
            block_size = l['block_size']
            url = l['url']
            l = certlib.retrieve_log_info(l, ses, get_block_size=False)
            l['block_size'] = block_size
            l['url'] = url

            calculated_chunks2 = max(int(l['tree_size']/l['block_size']), 1)
            percent_chunks2 = on_disk_chunks/calculated_chunks2
            calulated_missing_crts = max(0, (calculated_chunks2 - on_disk_chunks)) * l['block_size']

            run_log = os.stat(os.path.join(d, "run.log"))
            modified_time = run_log.st_mtime
            now = time.time()
            diff = int(now-modified_time)

            jimi = "J" if os.path.exists(os.path.join(d, "JIMI")) else " "
            print(f"{calulated_missing_crts}\t{diff}\t{percent_chunks2:.1%}\t{l['url']} ({jimi})")


def check_log(args):
    if os.path.exists(args.check_mode):
        logging.info("Input is a folder, looking for metadata...")
        meta_file = os.path.join(args.check_mode, "metadata")
        if os.path.exists(meta_file):
            with open(meta_file) as json_file:
                metadata = json.load(json_file)
                args.ctl_url = metadata['url']
                args.storage_dir = args.check_mode
        else:
            logging.error(f"Failed to find metadata in {args.check_mode}")
            sys.exit(1)
    else:
        args.ctl_url = args.check_mode
    logging.info("Checking log at URL {}".format(args.ctl_url))
    if not os.path.exists(args.storage_dir) or os.path.samefile(args.storage_dir, args.output_dir):
        logging.error("Storage dir did not exists or was same as base output dir: {}".format(args.storage_dir))
        return 1
    logging.info("Storage dir exists: {}".format(args.storage_dir))
    datafiles = sorted(glob.glob(os.path.join(args.storage_dir, '*.csv.gz')))
    ses = requests.Session()
    ses.verify = False
    log = setup_log_data(args, ses, False)
    empty = 0
    logging.info("Looping through {} datafiles:".format(len(datafiles)))
    percent20 = max(int(len(datafiles) / 20), 1)
    at_percent = 0
    index = 0
    for idx, gz in enumerate(datafiles):
    #for gz in datafiles:
        if idx % percent20 == 0:
            sys.stderr.write(f"{at_percent}% ")
            at_percent += 5
            sys.stderr.flush()
        #with gzip.open(gz, mode='rt') as f:
        try:
            #logging.info(gz)
            f = gzip.open(gz, mode='rt')
            # csv reader fails on \0 (why is there NUL in my data?) so we use for line in f.
            # if we choose to go back to csv we also need csv.field_size_limit(sys.maxsize) because
            # of https://crt.sh/?id=10751627
            for line in f:
                l = line.split(";")
                #try:
                if index > int(l[0]):
                    continue
                elif index != int(l[0]):
                    logging.error(f"index: {index}; l[0]: {int(l[0])}; chunk: {idx}")
                    logging.error(gz)
                    logging.info("Suggestion: ./simple.py -u '{}' -s {} -e {}".format(log['url'], index-10, int(l[0])+10))
                    sys.exit(0)
                index += 1
                if l[1].strip() == "":
                    # logging.error("index {} was empty!".format(line[0]))
                    empty += 1
            f.close()
            line = None
            l = None
            f = None
        except Exception as e:
            throw(e)
    sys.stderr.write("\n")
    if not args.no_check:
        logging.info("{operated_by}/{description}:".format(**log))
    logging.info("tree size: {:,}".format(log['tree_size']-1))
    len_diff = log['tree_size']-1-(index-1)
    logging.info(f"length: {index - 1:,} ({len_diff:,}, {len_diff / (log['tree_size'] - 1):.1%}), empty: {empty}")
    run_log = os.stat(os.path.join(args.storage_dir, "run.log"))
    modified_time = run_log.st_mtime
    now = time.time()
    diff = now-modified_time
    m, s = divmod(diff, 60)
    h, m = divmod(m, 60)
    logging.info('Last log update: {:d} hours, {:02d} minutes, {:02d} seconds'.format(int(h), int(m), int(s)))
    if diff < 120:
        logging.warning("run.log was last modified less than 120 seconds ago, a job is probably still running")
    logging.info("To continue: ./simple.py -u '{}' -s {}".format(log['url'], index-10))
    return 0


def main():
    parser = argparse.ArgumentParser(description='Pull down certificate transparency list information')
    parser.add_argument('-l', dest="list_mode", action="store_true", help="List all available certificate lists")
    parser.add_argument('-c', dest="check_mode", action="store", default=None,
                        help="Check the status of a log (bare url or folder)")
    parser.add_argument('-u', dest="ctl_url", action="store", default="", help="CTL url to download")
    parser.add_argument('-s', dest="ctl_start", action="store", type=int, default=0,
                        help="The CTL offset to start at (will be block aligned)")
    parser.add_argument('-e', dest="ctl_end", action="store", type=int, default=-1,
                        help="The CTL offset to end at (will be block aligned)")
    parser.add_argument('-o', dest="output_dir", action="store", default="./output",
                        help="The output directory to create log folders in")
    parser.add_argument('-t', dest="slp_time", action="store", type=int, default=0,
                                    help="Time (seconds) to wait between requests")
    parser.add_argument('-v', dest="verbose", action="store_true", help="Print out verbose/debug info")
    parser.add_argument('-x', dest="no_verify", action="store_true", help="Do not verify TLS certificates")
    parser.add_argument('-n', dest="no_check", action="store_true", help="Override URL check")
    parser.add_argument('-i', dest="sip", action="store", default=None, type=str, help="Source IP to use for requests")
    parser.add_argument('-g', dest="gua", action="store_true", help="Use generic user-agent")
    parser.add_argument('-a', dest="c_all_status", action="store_true", help="List estamated completion stats for all logs we find metadata files for")
    args = parser.parse_args()

    if args.list_mode:
        return logs_pretty_print(args)

    logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)

    if args.c_all_status:
        return all_log_status(args)

    if args.check_mode:
        args.storage_dir = glue_dir(args.output_dir, args.check_mode)
        return check_log(args)

    if args.ctl_url == "":
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    logging.info("Starting...")
    args.storage_dir = glue_dir(args.output_dir, args.ctl_url)
    return download_log(args)


if __name__ == "__main__":
    sys.exit(main())
