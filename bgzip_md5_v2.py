#!/usr/bin/env python3

"""Filter each named file through MD5 and bgzip in parallel.
If an input file is named "foo", files 
"""

import argparse
import logging
import os
import shlex
import subprocess
import sys

import gzip
import hashlib


logger = logging.getLogger(__name__)

MD5_LENGTH = 32  # The MD5 hex digest is always 32 characters.


def main():
    args = parse_args()
    config_logging(args)
    logger.debug('starting %r', args)
    compressing = not args.check
    checking = args.both or args.check
    exit_code = run(args.dest_dir, args.input_files, compressing, checking)
    logger.info('finished')
    logging.shutdown()
    sys.exit(exit_code)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-d', '--dest_dir',
                        help='If not specified, outputs are written'
                        ' to the same directories as the corresponding'
                        ' original files. Conflicts with --check.')
    parser.add_argument('-b', '--both', action='store_true',
                        help='both compress and check the results'
                        ' by decompressing and recomputing the MD5.'
                        ' Conflicts with --check.')
    parser.add_argument('-c', '--check', action='store_true',
                        help='In this case, input_files must by the .gz'
                        ' files. Only check that the decompressed .gz'
                        ' files have the correct MD5s. Conflicts with'
                        ' --dest_dir and --check.')
    parser.add_argument('input_files', nargs='*')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    if (args.dest_dir or args.both) and args.check:
        parser.error('Cannot have --check and also --dest_dir or --check.')
    return args


def config_logging(args):
    global logger
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger('bgzip_md5')


def run(dest_dir, input_files, compressing, checking):
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)
    encountered_errors = False
    for input_file_path in input_files:
        logger.info('processing %r', input_file_path)
        input_dir_path, file_name = os.path.split(input_file_path)
        output_dir_path = dest_dir or input_dir_path
        output_file_base = os.path.join(output_dir_path, file_name)
        gz_file_path = output_file_base + '.gz'
        md5_file_path = output_file_base + '.md5'
        if compressing:
            compress(input_file_path, file_name, gz_file_path, md5_file_path)
        if checking:
            logger.debug('checking %s', gz_file_path)
            try:
                hashes_match = check(gz_file_path, md5_file_path)
                if not hashes_match:
                    encountered_errors = True
            except Exception as e:
                logger.exception('error checking %s', gz_file_path)
                encountered_errors = True
    return encountered_errors
    

def compress(input_file_path, file_name, gz_file_path, md5_file_path):
    """Compress a single file, while computing the MD5 of the original."""
    template = "tee >(bgzip > {1}) < {0} | md5sum"
    cmd = template.format(shlex.quote(input_file_path),
                          shlex.quote(gz_file_path))
    logger.debug(cmd)
    proc = subprocess.run(['bash', '-c', cmd],
                          stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,
                          universal_newlines=True,
                          check=True)
    md5sum_line = proc.stdout.rstrip()
    assert md5sum_line[-1] == '-'
    md5sum_out_line = '{}{}\n'.format(md5sum_line[:-1], file_name)
    with open(md5_file_path, 'w') as fout:
        fout.write(md5sum_out_line)
    logger.debug(md5sum_out_line.rstrip())


def check(gz_file_path, md5_file_path):
    """Compare the checksum of the uncompressed data to the checksum stored in
    the MD5 file. Return True if they match, else log the missmatch and
    return False."""
    observed = compute_md5_of_uncompressed_data(gz_file_path)
    with open(md5_file_path) as fin:
        expected = fin.readline()[:MD5_LENGTH]
    if expected != observed:
        logger.error('MD5 mismatch for %, %s != %s', gz_file_path, expected, observed)
        return False
    return True


HASH_BLOCK_SIZE = 128 * 2 ** 10  # 128 kB
"""
def compute_md5_of_uncompressed_data(gz_file_path):
    #Return the hex digest of the corresponding uncompressed data.#
    md5_of_uncompressed_data = hashlib.md5()
    with gzip.open(gz_file_path) as fin:
        while True:
            data = fin.read(HASH_BLOCK_SIZE)
            if not data:
                break
            md5_of_uncompressed_data.update(data)
    return md5_of_uncompressed_data.hexdigest() 
"""

def compute_md5_of_uncompressed_data(gz_file_path):
    """Return the hex digest of the corresponding uncompressed data."""
    zcat = subprocess.Popen(['zcat', gz_file_path],
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE)
    md5sum = subprocess.Popen('md5sum',
                              stdin=zcat.stdout,
                              stdout=subprocess.PIPE)
    out, err = md5sum.communicate()
    if md5sum.returncode:
        raise Exception('md5sum returned error %s for %s', md5sum.returncode, gz_file_path)
    zcat.wait()
    if zcat.returncode:
        raise Exception('zcat returned error %s for %s', zcat.returncode, gz_file_path)
    return out[:MD5_LENGTH].decode('ascii')

    
if __name__ == '__main__':
    main()
