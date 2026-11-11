File Integrity Checker

A Python command-line tool that detects changes to file contents by comparing SHA-256 hashes against a saved baseline. Built as a learning project for file integrity checking, with log files as a practical use case.

The tool reports whether a file matches its recorded hash. It does not determine whether a change was authorized, prevent changes, or monitor files continuously.

## Features

- Calculate SHA-256 hashes using 4 KB chunks instead of loading entire files into memory.
- Initialize a baseline for a single file or the files directly inside a directory.
- Store each file's hash, baseline timestamp, and size in `integrity_hashes.json`.
- Check an individual file and report `Unmodified` or `Modified`.
- Update a baseline after reviewing and accepting a legitimate change.
- Print error messages for missing files and permission errors.

## Requirements

- Python 3. The walkthrough below was verified with Python 3.12.
- A Python installation with `tkinter` available. The current script imports `tkinter.ttk.Style`, although it does not use a graphical interface.
- Git, if cloning the repository.

No third-party Python packages are required. If importing `tkinter` fails, install Tk support for your Python distribution. It is not a dependency to install with `pip`.

The examples use `python -X utf8` so the script's status symbols can be printed on Windows. If your Python 3 command is `python3`, use that instead of `python` throughout.

## Get started

```sh
git clone https://github.com/syngyskadyr/File-Integrity-Checker-.git
cd File-Integrity-Checker-
python -X utf8 -c "import tkinter; print('Python and tkinter are available')"
```

The executable script is **`hashing.py`**. Its built-in usage text currently refers to `integrity_check.py`; use the filename shown in this README.

## Commands

Run these commands from the repository directory. Quote paths that contain spaces.

| Command | Behavior |
| --- | --- |
| `python -X utf8 hashing.py init <path>` | Create or replace baseline entries for one file or the direct files in a directory. Subdirectories are skipped. |
| `python -X utf8 hashing.py check <filepath>` | Compare one file's current hash with its saved baseline. |
| `python -X utf8 hashing.py update <filepath>` | Save the file's current contents as the new baseline. Creates an entry if none exists. |

Both `init` and `update` replace existing hashes for the files they process. Run `check` before accepting changes, and establish baselines only from files you trust.

## Walkthrough: detect a changed file

Run the following from the repository directory. Use a new `demo` directory: this keeps the example file and its hash database separate from the files already in the repository. The commands work in PowerShell and common Unix shells with Python 3 available as `python`.

### 1. Create a file and record its baseline

```sh
mkdir demo
cd demo
python -X utf8 -c "from pathlib import Path; Path('demo.log').write_text('Login successful\n', encoding='utf-8')"
python -X utf8 ../hashing.py init demo.log
python -X utf8 ../hashing.py check demo.log
```

The check includes:

```text
✓ Status: Unmodified
```

### 2. Change the file and check again

```sh
python -X utf8 -c "from pathlib import Path; p = Path('demo.log'); p.write_text(p.read_text(encoding='utf-8') + 'Configuration changed\n', encoding='utf-8')"
python -X utf8 ../hashing.py check demo.log
```

The check now includes:

```text
⚠ Status: Modified
```

It also prints the stored hash, current hash, and saved baseline timestamp. Hash values depend on the file's exact contents.

### 3. Accept the change after reviewing it

```sh
python -X utf8 ../hashing.py update demo.log
python -X utf8 ../hashing.py check demo.log
```

The check returns `Unmodified` because the new contents now match the updated baseline. The example leaves its files in `demo`; it does not change the repository's existing hash database.

## How it works

1. Read a file in binary mode, 4,096 bytes at a time.
2. Compute its SHA-256 digest with Python's `hashlib` module.
3. On `init` or `update`, save the digest, file size in bytes, and local timestamp in JSON, keyed by the supplied file path.
4. On `check`, calculate the digest again and compare it with the saved hash. Checking does not update the baseline.

`integrity_hashes.json` is read and written in the **current working directory**, not necessarily alongside the script. Use the same working directory and the same path spelling for initialization and subsequent checks. For example, `demo.log`, `./demo.log`, and an absolute path are different database keys.

## Current limitations

- **Manual checks only.** There is no background service, scheduled scanning, or notification system.
- **Limited directory support.** `init` processes direct files only; `check` accepts one file. There is no directory-wide report of added or deleted files. A missing file produces an error message.
- **The baseline must be protected separately.** The JSON database is not signed or authenticated. Someone who can change both a file and its stored hash can make the altered contents pass a check. A match confirms equality with the baseline, not that the baseline was trustworthy.
- **No automatic database exclusion.** Avoid initializing a directory containing the active `integrity_hashes.json`: the script can hash that database and then change it while saving results. Keep the database outside the directory being checked.
- **Content comparison only.** File permissions and ownership are not checked. The stored size is metadata; the comparison uses the hash. The output label `Last verified` refers to the last baseline initialization or update, not the most recent successful check.
- **Exit codes are not a reliable integrity signal.** A modified file and several handled error cases still return exit code `0`. Read the output; do not rely on the exit code for automated security decisions.
- **Database errors need attention.** If reading or parsing the database fails, the script prints an error and uses an empty dictionary. A later `init` or `update` can overwrite the existing database. Back it up and investigate the error before continuing.

This is an educational utility for understanding hashing and baseline comparison. It is not a production intrusion detection system.

## Repository contents

| File | Purpose |
| --- | --- |
| `hashing.py` | Hashing, JSON storage, integrity checks, and command-line dispatch. |
| `integrity_hashes.json` | Included hash database; establish your own trusted baseline for your files. |
| `application.log`, `auth.log`, `syslog.txt`, `test_log.txt` | Included files that can be used to explore the checker. |
| `LICENSE` | MIT license terms. |

## License

Released under the [MIT License](LICENSE).
