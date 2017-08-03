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


logger = logging.getLogger(__name__)


def main():
    args = parse_args()
    config_logging(args)
    logger.debug('starting %r', args)
    compressing = not args.check
    checking = args.both or args.check
    run(args.dest_dir, args.input_files, compressing, checking)
    logger.info('finished')
    logging.shutdown()


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
            pass


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


if __name__ == '__main__':
    main()
