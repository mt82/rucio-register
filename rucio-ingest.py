#!/usr/bin/env python3

# Ingests files for rucio non-deterministic rse

import os
import argparse
import copy
import json
import logging
import time
import random

import gfal2
import samweb_client
from rucio.client import Client as RucioClient
from rucio.client.uploadclient import UploadClient
from rucio.client.didclient import DIDClient
from rucio.client.ruleclient import RuleClient
from rucio.common.exception import (DataIdentifierNotFound, RSEWriteBlocked, InputValidationError, NoFilesUploaded)
from rucio.rse import rsemanager as rsemgr

logging.basicConfig(format='%(asctime)-15s %(name)s %(levelname)s %(message)s', level=logging.INFO)
logger = logging.getLogger('ndrseipi')


class InPlaceIngestClient(UploadClient):
    def __init__(self, _client=None, logger=None, tracing=True, ctxt=None, target_dir=None):
        super().__init__(_client, logger, tracing)
        self.ctxt = ctxt
        self.target_dir = target_dir


    def _upload_item(self, rse_settings, rse_attributes, lfn,
                     source_dir=None, domain='wan', impl=None,
                     force_pfn=None, force_scheme=None, transfer_timeout=None,
                     delete_existing=False, sign_service=None) -> str:
        """Override _upload_item"""
        pfn = force_pfn
        return pfn

    def ingest(self, items, summary_file_path=None, traces_copy_out=None, ignore_availability=False, activity=None):

        def _pick_random_rse(rse_expression):
            rses = [r['rse'] for r in self.client.list_rses(rse_expression)]  # can raise InvalidRSEExpression
            random.shuffle(rses)
            return rses[0]

        logger = self.logger
        files = self._collect_and_validate_file_info(items)
        # self._register_file()
        print(files)

        registered_dataset_dids = set()
        registered_file_dids = set()
        rse_expression = None
        for file in files:
            rse_expression = file['rse']
            rse = self.rse_expressions.setdefault(rse_expression, _pick_random_rse(rse_expression))

            if not self.rses.get(rse):
                rse_settings = self.rses.setdefault(rse, rsemgr.get_rse_info(rse, vo=self.client.vo))
                if not ignore_availability and rse_settings['availability_write'] != 1:
                    raise RSEWriteBlocked('%s is not available for writing. No actions have been taken' % rse)

            dataset_scope = file.get('dataset_scope')
            dataset_name = file.get('dataset_name')
            file['rse'] = rse
            if dataset_scope and dataset_name:
                dataset_did_str = f'{dataset_scope}:{dataset_name}'
                file['dataset_did_str'] = dataset_did_str
                registered_dataset_dids.add(dataset_did_str)
            
            registered_file_dids.add(f'{file["did_scope"]}:{file["did_name"]}')
        wrong_dids = registered_file_dids.intersection(registered_dataset_dids)
        if len(wrong_dids):
            raise InputValidationError('DIDs used to address both files and datasets: %s' % str(wrong_dids))
        logger(logging.DEBUG, 'Input validation done.')

        registered_dataset_dids = set()
        num_succeeded = 0
        num_already_exists = 0
        summary = []
        for file in files:
            basename = file['basename']
            logger(logging.INFO, 'Preparing ingest for file %s' % basename)

            no_register = file.get('no_register')
            register_after_upload = file.get('register_after_upload') and not no_register
            pfn = file.get('pfn')
            force_scheme = file.get('force_scheme')
            impl = file.get('impl')
            delete_existing = False

            trace = copy.deepcopy(self.trace)
            # appending trace to list reference, if the reference exists
            if traces_copy_out is not None:
                traces_copy_out.append(trace)

            rse = file['rse']
            trace['scope'] = file['did_scope']
            trace['datasetScope'] = file.get('dataset_scope', '')
            trace['dataset'] = file.get('dataset_name', '')
            trace['remoteSite'] = rse
            trace['filesize'] = file['bytes']

            file_did = {'scope': file['did_scope'], 'name': file['did_name']}
            dataset_did_str = file.get('dataset_did_str')
            rse_settings = self.rses[rse]
            rse_sign_service = rse_settings.get('sign_url', None)
            is_deterministic = rse_settings.get('deterministic', True)

            # TODO: If deterministic, check the path with a calculated path
            if not is_deterministic and not pfn:
                logger(logging.ERROR, 'PFN has to be defined for NON-DETERMINISTIC RSE.')
                continue
            if pfn and is_deterministic:
                logger(logging.WARNING, 'Upload with given pfn implies that no_register is True, except non-deterministic RSEs')
                no_register = True

            # resolving local area networks
            domain = 'wan'
            rse_attributes = {}
            try:
                rse_attributes = self.client.list_rse_attributes(rse)
            except:
                logger(logging.WARNING, 'Attributes of the RSE: %s not available.' % rse)
            if (self.client_location and 'lan' in rse_settings['domain'] and 'site' in rse_attributes):
                if self.client_location['site'] == rse_attributes['site']:
                    domain = 'lan'
            logger(logging.DEBUG, '{} domain is used for the upload'.format(domain))

            if not no_register and not register_after_upload:
                self._register_file(file, registered_dataset_dids, ignore_availability=ignore_availability, activity=activity)

            # if register_after_upload, file should be overwritten if it is not registered
            # otherwise if file already exists on RSE we're done
            if register_after_upload:
                if rsemgr.exists(rse_settings, pfn if pfn else file_did, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    try:
                        self.client.get_did(file['did_scope'], file['did_name'])
                        logger(logging.INFO, 'File already registered. Skipping upload.')
                        trace['stateReason'] = 'File already exists'
                        continue
                    except DataIdentifierNotFound:
                        logger(logging.INFO, 'File already exists on RSE. Previous left overs will be overwritten.')
                        delete_existing = True
            elif not is_deterministic and not no_register:
                if rsemgr.exists(rse_settings, pfn, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    logger(logging.INFO, 'File already exists on RSE with given pfn. Skipping upload. Existing replica has to be removed first.')
                    trace['stateReason'] = 'File already exists'
                    num_already_exists += 1
                    continue
                elif rsemgr.exists(rse_settings, file_did, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    logger(logging.INFO, 'File already exists on RSE with different pfn. Skipping upload.')
                    trace['stateReason'] = 'File already exists'
                    num_already_exists += 1
                    continue
            else:
                if rsemgr.exists(rse_settings, pfn if pfn else file_did, domain=domain, scheme=force_scheme, impl=impl, auth_token=self.auth_token, vo=self.client.vo, logger=logger):
                    logger(logging.INFO, 'File already exists on RSE. Skipping upload')
                    trace['stateReason'] = 'File already exists'
                    num_already_exists += 1
                    continue
            
            num_succeeded += 1
            trace['transferEnd'] = time.time()
            trace['clientState'] = 'DONE'
            file['state'] = 'A'
            logger(logging.INFO, 'Successfully ingested file %s' % basename)
            self._send_trace(trace)

            # Commented by mt
            self._register_file(file, registered_dataset_dids, ignore_availability=ignore_availability, activity=activity)
            if dataset_did_str:
                try:
                    # Commented by mt
                    self.client.attach_dids(file['dataset_scope'], file['dataset_name'], [file_did])
                    pass
                except Exception as error:
                    logger(logging.WARNING, 'Failed to attach file to the dataset')
                    logger(logging.DEBUG, 'Attaching to dataset {}'.format(str(error)))
        
        if num_succeeded == 0:
            if num_already_exists > 0:
                logger(logging.INFO, f'{num_already_exists} files skipped since the files already exists on RSE')
            else:
                raise NoFilesUploaded()
        return 0

    def _collect_file_info(self, filepath, item):
        """
        Collects infos (e.g. size, checksums, etc.) about the file and
        returns them as a dictionary
        (This function is meant to be used as class internal only)

        :param filepath: path where the file is stored
        :param item: input options for the given file

        :returns: a dictionary containing all collected info and the input options
        """
        new_item = copy.deepcopy(item)
        new_item['path'] = filepath
        new_item['dirname'] = filepath
        new_item['basename'] = filepath.split('/')[-1]

        file_stats = self.ctxt.lstat(filepath)

        new_item['bytes'] = file_stats.st_size

        try:
            adler32 = self.ctxt.checksum(filepath, 'adler32')
            new_item['adler32'] = adler32
        except Exception as e:
            logger.error(f'cannot get adler32 checksum for {filepath}')
            raise

        try:
            md5 = self.ctxt.checksum(filepath, 'md5')
        except Exception as e:
            logger.error(f'could not get md5 checksum for {filepath}')
            raise

        new_item['md5'] = md5
        new_item['meta'] = {'guid': self._get_file_guid(new_item)}
        new_item['state'] = 'C'
        if not new_item.get('did_scope'):
            new_item['did_scope'] = self.default_file_scope
        if not new_item.get('did_name'):
            new_item['did_name'] = new_item['basename']

        return new_item

    def _collect_and_validate_file_info(self, items):
        """
        Checks if there are any inconsistencies within the given input
        options and stores the output of _collect_file_info for every file
        (This function is meant to be used as class internal only)

        :param filepath: list of dictionaries with all input files and options

        :returns: a list of dictionaries containing all descriptions of the files to upload

        :raises InputValidationError: if an input option has a wrong format
        """
        logger = self.logger
        files = []
        for item in items:
            path = item.get('path')
            pfn = item.get('pfn')

            if not path:
                path = pfn
            if not item.get('rse'):
                logger(logging.WARNING, 'Skipping file %s because no rse was given' % path)
                continue
            if pfn:
                item['force_scheme'] = pfn.split(':')[0]
            if item.get('impl'):
                impl = item.get('impl')
                impl_split = impl.split('.')
                if len(impl_split) == 1:
                    impl = 'rucio.rse.protocols.' + impl + '.Default'
                else:
                    impl = 'rucio.rse.protocols.' + impl
                item['impl'] = impl
            file = self._collect_file_info(path, item)
            files.append(file)

        return files


def get_files(ctxt, pfns: list, rse: str, scope: str, dataset: str) -> list:

    items = []
    for pfn in pfns:
        name = os.path.basename(pfn)
        f_stat = ctxt.lstat(pfn)
        size = f_stat.st_size
        adler32 = ctxt.checksum(pfn, 'adler32')
        
        # Commented by mt
        # here we have to add dataset_scope 
        # and dataset_name so that did will 
        # be attache to it
        replica = {
            'name': name,
            'bytes': size,
            'adler32': adler32,
            'path': pfn,
            'pfn': pfn,
            'rse': rse,
            'dataset_scope': scope,
            'dataset_name': dataset,
            'register_after_upload': True
        }
        items.append(replica)

    return items


#def discover_files(ctxt, rse: str, directory: str, scope: str) -> list:
#    '''Discover files on the server to be ingested
#    '''
#    # get contents of a directory
#    files = ctxt.listdir(directory)
#
#    items = []
#    # build pfns
#    for f in files:
#        name = f
#        pfn = f'{directory}/{f}'
#        f_stat = ctxt.lstat(pfn)
#        size = f_stat.st_size
#        adler32 = ctxt.checksum(pfn, 'adler32')
#
#        replica = {
#            'name': name,
#            'scope': scope,
#            'bytes': size,
#            'adler32': adler32,
#            'path': pfn,
#            'pfn': pfn,
#            'rse': rse,
#            'register_after_upload': True
#        }
#        items.append(replica)
#
#    return items


#def inplace_ingest(target_dir, rse):
#    ctxt = gfal2.creat_context()
#
#    rucio_client = RucioClient()
#    inplace_ingest_client = InPlaceIngestClient(rucio_client, logger=logger, ctxt=ctxt)
#
#    rse_info = rucio_client.get_rse(rse=rse)
#    rse_attributes = rucio_client.list_rse_attributes(rse)
#    print(rse_attributes)
#    print(rse_info)
#    protocol = target_dir.split(":")[0]
#    print([p['prefix'] for p in rse_info["protocols"] if p['scheme'] == protocol])
#
#    items = discover_files(ctxt, rse, target_dir, 'user.dylee')
#
#    inplace_ingest_client.upload(items)


def inplace_ingest2(files, rse, scope, dataset):
    ctxt = gfal2.creat_context()

    rucio_client = RucioClient()
    inplace_ingest_client = InPlaceIngestClient(rucio_client, logger=logger, ctxt=ctxt)

    #rse_info = rucio_client.get_rse(rse=rse)
    #rse_attributes = rucio_client.list_rse_attributes(rse)

    # Checks to see if RSE is deterministic
    #if rse_info['deterministic']:
    #    raise Exception("Needs to be a non-deterministic RSE")

    #protocol = target_dir.split(":")[0]
    #files = ctxt.listdir(target_dir) 
    items = get_files(ctxt, files, rse, scope, dataset)
    inplace_ingest_client.ingest(items)


def get_file_list_from_samweb(dimensions=None, defname=None):
    rse = 'FNAL_ENSTORE'
    cl = samweb_client.SAMWebClient(experiment='icarus')
    files_name = [f for f in cl.listFiles(dimensions=dimensions, defname=defname)]
    files_uri = []
    for f in files_name:
        uri = cl.getFileAccessUrls(f, schema='srm', locationfilter='enstore')
        if len(uri) > 0:
            files_uri.append(uri[0].replace('fndca1.fnal.gov','fndcadoor.fnal.gov'))
    return files_uri, rse


def get_parser():
    parser = argparse.ArgumentParser(
        description='''Rucio Ingest: scans for existing files
        using gfal2 and register into a non-deterministic RSE without copying''')
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument(
        '-r',
        nargs='+',
        required=False,
        help='Run number',
        metavar='RUN_NUMBER',
        dest='run_numbers')
    grp.add_argument(
        '-dim',
        nargs=1,
        required=False,
        help='Samweb dimensions',
        metavar='SAMWEB_DIMENSIONS',
        dest='dimensions')
    grp.add_argument(
        '-def',
         nargs=1,
         required=False,
         help='Samweb definition',
         metavar='SAMWEB_DEFINITION',
         dest='definition')
    parser.add_argument(
        '-ds',
        nargs=1,
        required=True,
        help='Dataset name in which files will be grouped',
        metavar='DATASET',
        dest='dataset')
    parser.add_argument(
        '-s',
        nargs='+',
        required=False,
        default='BEAM',
        choices=['ALL', 'BEAM', 'OFFBEAM', 'NUMI', 'BNB', 'OFFBEAMNUMI', 'OFFBEAMBNB', 'NUMIMAJORITY', 'BNBMAJORITY', 'NUMIMINBIAS', 'BNBMINBIAS', 'OFFBEAMNUMIMAJORITY', 'OFFBEAMBNBMAJORITY', 'OFFBEAMNUMIMINBIAS', 'OFFBEAMBNBMINBIAS'],
        help='Data stream',
        metavar='DATA_STREAM',
        dest='data_streams')
    parser.add_argument(
        '-rse',
        nargs='+',
        default='INFN_CNAF_DISK_TEST',
        choices=['INFN_CNAF_DISK_TEST', 'INFN_CNAF_TAPE', 'FNAL_DCACHE', 'FNAL_ENSTORE'],
        required=False,
        help='RSE where dataset will be replicated',
        metavar='RSE',
        dest='rses')

    return parser


def get_program_arguments():
    parser = get_parser()
    args = parser.parse_args()
    return args


def get_data_streams(streams):
    ALL = {'BEAM': ['numi', 'bnb', 'numimajority', 'bnbmajority', 'numiminbias', 'bnbminbias'], 'OFFBEAM': ['offbeamnumi', 'offbeambnb', 'offbeamnumimajority', 'offbeambnbmajority', 'offbeamnumiminbias', 'offbeambnbminbias']}
    data_streams = []
    for d in streams:
       if d == 'ALL' or d == 'BEAM':
           data_streams += ALL['BEAM']
       if d == 'ALL' or d == 'OFFBEAM':
           data_streams += ALL['OFFBEAM']
       if d != "ALL" and d != "BEAM" and d != "OFFBEAM":
           data_streams.append(d.lower())
    return set(data_streams)


def get_dimensions(runs, streams):
    dimensions = '('
    for r in runs:
       dimensions += f'run_number = {r} or '
    dimensions = dimensions[:-4] + ')'
    dimensions += " and ("
    for d in get_data_streams(streams):
       dimensions += f'data_stream = {d} or '
    dimensions = dimensions[:-4] + ')'
    dimensions += " and (data_tier = raw)"
    return dimensions


def main():
    args = get_program_arguments()
    dataset = args.dataset[0]
    scope = 'user.icaruspro'
    rses_dest = args.rses
    definition = None
    dimensions = None
    if args.definition:
       definition = args.definition[0]
    if args.dimensions:
       dimensions = args.dimensions[0]
    if args.run_numbers:
       dimensions=get_dimensions(args.run_numbers, args.data_streams)
    print(f"definition={definition}")
    print(f"dimensions={dimensions}")
    files_uri, rse_orig = get_file_list_from_samweb(dimensions=dimensions, defname=definition)
    
    try:
        dc = DIDClient()
        dc.add_dataset(scope, dataset)
        print(f"[INFO]: dataset {scope}:{dataset} added!!")
    except:
        pass
    
    if rses_dest:
        for rse in rses_dest:
            try:
                rc = RuleClient()
                rc.add_replication_rule([{"scope":scope, "name": dataset}], 1, rse)
                print(f"[INFO]: rule for dataset {scope}:{dataset} to rse {rse} added!!")
            except:
                pass

    # for f in files_uri:
    #     print(f)
    # here a function providing list of pfns from samweb
    inplace_ingest2(files_uri, rse_orig, scope, dataset)


if __name__ == '__main__':
    main()
