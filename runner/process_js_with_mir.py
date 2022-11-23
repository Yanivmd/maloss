import argparse
import logging
from datetime import datetime
from pathlib import Path
import subprocess
import json
import csv
from shutil import rmtree
from time import time

from pyutils.common_functions import get_elapsed_str, include_exclude_yielder

logging.root.setLevel(logging.INFO)

TIMEOUT_MINS = 30

parser = argparse.ArgumentParser(description="Perform analysis on samples")
parser.add_argument('--include', type=str, default=None, help="Must include string | (comma separated strings)")
parser.add_argument('--exclude', type=str, default=None, help="Exclude this(es) string | (comma separated strings)")
parser.add_argument('--reuse', action='store_true', help='reuse existing or skip existing')
parser.add_argument('--cache-only', action='store_true', help='reuse existing or skip existing')
args = parser.parse_args()

if args.cache_only and args.reuse:
    logging.error("cache_only can't be used with reuse (choose one)")
    exit()


def csv_prep(s):
    return str(s).replace(",", ";")


reuse = args.reuse
logging.warning(f"REUSE={args.reuse}")

apis = []
for line in Path("/var/local/maloss/runner/apis").read_text().splitlines():
    l = line.strip()
    if len(l) > 0:
        full_api = l.split(': ')[1][1:-1]
        apis.append(full_api)
        sections = full_api.split('.')
        if len(sections) == 1:
            apis.append(f"require('{sections[0]}')")
        elif len(sections) > 1:
            apis.append(f"require('{sections[0]}')" + '.' + '.'.join(sections[1:]))

apis = set(apis)

sample_dirs_root = Path('/var/local/maloss/dataset/')
all_results = {}
fields_str = "label,package_name,group,system,run_timestamp,sinks_added,sinks_removed,sinks_changed,before_version,after_version,before_weakly_connected_components,after_weakly_connected_components,before_running_time,after_running_time,before_error,after_error,suspicious,system_extra_info"
csv_entries = []
for samples_dir_path in sample_dirs_root.glob("*"):
    if not samples_dir_path.is_dir():
        continue
    samples_dir_name = samples_dir_path.name
    logging.debug(f"Starting samples dir: {samples_dir_name}")
    samples_dir_results = {}
    for sample in include_exclude_yielder(samples_dir_path.glob("*-->*"), args.include, args.exclude,
                                          key=lambda s: s.as_posix()):
        sample_name = sample.name
        logging.info(f"Starting sample:{sample_name}")
        old_v_and_pack, new_v = sample.name.split('-->')
        pack_name, old_v = old_v_and_pack.split("_")
        empty = True
        try:
            old_tgz = list(sample.rglob(f"{pack_name}-{old_v}.tgz"))[0]
            new_tgz = list(sample.rglob(f"{pack_name}-{new_v}.tgz"))[0]
        except Exception as e:
            print(f"{e.__class__.__name__}:{e};Error processing:{sample_name}")
            samples_dir_results[sample_name] = {"error": "Sample code not found."}
            continue

        empty = False

        out_dir = sample.joinpath("comp_res")
        out_file = out_dir.joinpath("OUTFILE")
        out_runtime = out_dir.joinpath('masloss-runtime.json')
        do_processing = True
        sample_error_log = None
        if out_dir.exists():
            if args.reuse or args.cache_only:
                do_processing = False
            else:
                rmtree(out_dir)
        else:
            if args.cache_only:
                continue

        if do_processing:
            logging.info(f"Processing sample:{sample_name}")
            out_dir.mkdir()
            with out_dir.joinpath("run.log").open("w") as out_log, out_dir.joinpath("err.log").open("w") as err_log:
                maloss_args = ["python", "main.py", "compare_ast", "-i", new_tgz.as_posix(), old_tgz.as_posix(), "-l",
                        "javascript",
                        "-c", "../config/astgen_javascript_smt.config", "-o", out_dir.as_posix(), "--outfile",
                        out_file.as_posix()]
                try:
                    start_time = time()
                    run_result = subprocess.run(maloss_args, timeout=60 * TIMEOUT_MINS, stdout=out_log,
                                                stderr=err_log)
                    runtime = get_elapsed_str(start_time)
                except subprocess.TimeoutExpired as e:
                    out = f"{e.__class__.__name__}:{e};Timeout processing:{sample_name}"
                    print(out)
                    sample_error_log = out
                    runtime = "0:0:0"
                    out_dir.joinpath("timeout").write_text(json.dumps(f"TIMEOUT_MINS=={TIMEOUT_MINS}"))
                finally:
                    out_runtime.write_text(json.dumps(runtime))

        try:
            runtime_json = json.load(out_runtime.open("r"))
        except Exception as e:
            print(f"{e.__class__.__name__}:{e};You are holding broken results. :{sample_name}")
            print("Exiting now.")
            exit()
        new_entry = {
            'package_name': sample_name,
            'group': samples_dir_name,
            'run_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S."),
            'before_version': old_v,
            'after_version': new_v,
            'before_running_time': runtime_json,
            'after_running_time': runtime_json,
            'label': "MAL" if 'backstab' in samples_dir_name else "BEN"
        }

        maloss_taint = new_entry.copy()
        maloss_taint['system'] = 'maloss_taint'
        csv_entries.append(maloss_taint)

        maloss_new_api = new_entry.copy()
        maloss_new_api['system'] = 'maloss_new_api'
        csv_entries.append(maloss_new_api)

        maloss_new_sus_api = new_entry.copy()
        maloss_new_sus_api['system'] = 'maloss_new_sus_api'
        csv_entries.append(maloss_new_sus_api)

        try:
            res_json = json.load(out_file.open("r"))
        except json.JSONDecodeError as e:
            out = f"{e.__class__.__name__}:{e};JSON RELATED ERROR:{sample_name}"
            print(out)
            sample_error_log = out
        except FileNotFoundError as e:
            out = f"{e.__class__.__name__}:{e};ANALYSIS ERROR:{sample_name}"
            print(out)
            sample_error = True
        else:
            res_keys = list(res_json.keys())
            old_key = list(filter(lambda x: old_v in Path(x).name, res_keys))
            assert (len(old_key) == 1)
            old_key = old_key[0]
            new_key = list(filter(lambda x: new_v in Path(x).name, res_keys))
            if len(new_key) > 1:
                # to handle `/var/local/maloss/dataset/BenignSamples/standard_17.0.0-2-->17.0.0`
                new_key.remove(old_key)
            assert (len(new_key) == 1)
            new_key = new_key[0]
            new_result = res_json[new_key]
            has_sink = any(map(lambda x: "SINK" in x, new_result['permissions']))
            has_source = any(map(lambda x: "SOURCE" in x, new_result['permissions']))

            maloss_taint['suspicious'] = has_sink and has_source
            maloss_taint['system_extra_info'] = csv_prep(new_result['permissions'])

            maloss_new_api['suspicious'] = len(new_result['uniq_apis']) > 0
            maloss_new_api['system_extra_info'] = csv_prep(new_result['uniq_apis'])

            sus_apis = set(new_result['uniq_apis']).intersection(apis)
            maloss_new_sus_api['suspicious'] = len(sus_apis) > 0
            maloss_new_sus_api['system_extra_info'] = csv_prep(sus_apis)

        for x in [maloss_taint, maloss_new_api, maloss_new_sus_api]:
            x['before_error'] = sample_error_log is None
            x['after_error'] = sample_error_log is None
            x['system_extra_info'] = csv_prep(sample_error_log)

sample_dirs_root.joinpath('masloss-result.json').write_text(json.dumps(all_results, indent="\t"))

with sample_dirs_root.joinpath('masloss-result.csv').open('w') as f:
    dwr = csv.DictWriter(f, fieldnames=fields_str.split(","))
    dwr.writeheader()
    for l in csv_entries:
        dwr.writerow(l)

"""

export pkg=../testdata/eslint-scope_4.0.0__3.7.2/eslint-scope-3.7.2.tgz
export pkgbefore=../testdata/eslint-scope_4.0.0__3.7.2/eslint-scope-4.0.0.tgz
export out=../testdata/eslint-scope_4.0.0__3.7.2/eslint-scope-3.7.2.tgz.out
export pkgname=eslint-scope

 python main.py astgen -l javascript  $pkg ${out}.astgen.txt -c ../config/test_astgen_javascript.config

(Download ?`?) python main.py astfilter -n eslint-scope -c $javascript_config -d ../testdata/ -o ../testdata/ -l javascript
mkdir $out.taint 
python main.py taint -n $pkgname -i $pkg -d /data/maloss/info/javascript --ignore_dep -o $out.taint -l javascript -c ../config/astgen_javascript_smt.config

python main.py static -n $pkgname -c $python_config -d ../testdata/ -o ../testdata/

mkdir $out.comp
python main.py compare_ast -i $pkg $pkgbefore -l javascript -c ../config/astgen_javascript_smt.config -o $out.comp׳

"""
