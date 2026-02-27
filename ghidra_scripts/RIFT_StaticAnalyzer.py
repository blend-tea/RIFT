# @category Rust
# @author blend-tea

import typing

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.util import DefinedStringIterator
from ghidra.util.exception import CancelledException
from java.lang import IllegalArgumentException
from ghidra.app.util.bin import MemoryByteProvider
from ghidra.app.util.bin.format.pe import PortableExecutable
from ghidra.app.util.bin.format.pe.rich import CompId, RichHeaderRecord
import re

try:
    # Python 3
    from urllib.request import urlopen
except ImportError:
    # Jython
    from urllib2 import urlopen
import json
import base64
import os

RUSTC_HASHES_PATH = r"C:/Users/relap/ghidra_scripts/RIFT/data/rustc_hashes.json"

RE_RUSTLIB = (
    r".{1,250}[\\|\/](.{1,50}-\d+\.\d+\.\d+(-.{1,20})?)[\\|\/]src[\\|\/].{1,100}\.rs"
)
RE_COMMITHASH = r".{1,250}rustc[\\|\/]([0-9a-zA-Z]{40})[\\|\/]"


def get_crates(sc):
    crates = set()
    for s in sc:
        m = re.match(RE_RUSTLIB, s)
        if m:
            crates.add(m.group(1))

    return list(crates)


def get_commithash(sc):
    commithash = None
    for s in sc:
        m = re.match(RE_COMMITHASH, s)
        if not m:
            continue
        commithash = m.group(1)
        break

    return commithash


def detect_arch():
    """
    Automatically detect architecture from current program.
    Returns the architecture string (x86_64, i686, aarch64, arm, mips64, mips) or None if detection fails.
    """
    try:
        # Get processor name
        language = currentProgram.getLanguage()
        processor = language.getProcessor()
        processor_name = str(processor).lower()

        # Get architecture size (32 or 64 bits)
        size = language.getLanguageDescription().getSize()

        print(f"Detected processor: {processor}, size: {size} bits")

        # Map processor to Rust architecture names
        if "x86" in processor_name:
            if size == 64:
                return "x86_64"
            elif size == 32:
                return "i686"
        elif "aarch64" in processor_name or "arm64" in processor_name:
            return "aarch64"
        elif "arm" in processor_name:
            if size == 64:
                return "aarch64"
            elif size == 32:
                return "arm"
        elif "mips" in processor_name:
            if size == 64:
                return "mips64"
            elif size == 32:
                return "mips"

        # If we can't determine, print warning and return None
        print(
            f"Warning: Could not automatically detect architecture for processor '{processor}' (size: {size} bits)"
        )
        print("Falling back to manual selection...")
        return None

    except Exception as e:
        print(f"Error detecting architecture: {str(e)}")
        print("Falling back to manual selection...")
        return None


def ask_arch():
    """
    Ask user to select architecture (fallback when auto-detection fails)
    """
    try:
        from java.util import ArrayList

        choices = ArrayList()
        choices.add("x86_64")
        choices.add("i686")
        choices.add("aarch64")
        choices.add("arm")
        choices.add("mips64")
        choices.add("mips")
        choice = askChoice(
            "Architecture Selection", "Select Architecture:", choices, "x86_64"
        )
        return str(choice)
    except CancelledException:
        print("User cancelled architecture selection. Exiting...")
        return None
    except Exception as e:
        print("Error asking for architecture: " + str(e))
        return None


def get_comp_id_info():
    """
    Rich HeaderからCompId情報を取得
    Returns: (has_rich_header, product_descriptions) tuple
    """
    try:
        memory = currentProgram.getMemory()
        provider = MemoryByteProvider(memory, currentProgram.getImageBase())
        pe = PortableExecutable(provider, PortableExecutable.SectionLayout.MEMORY)
        rich_header = pe.getRichHeader()

        if rich_header is None or rich_header.getSize() == 0:
            return False, []

        records = rich_header.getRecords()
        product_descriptions = []

        for record in records:
            comp_id = record.getCompId()
            desc = comp_id.getProductDescription()
            if desc:
                product_descriptions.append(desc)

        return True, product_descriptions
    except Exception as e:
        # PEファイルでない場合など、エラーが発生する可能性がある
        return False, []


def detect_msvc_mingw_from_comp_id():
    """
    CompIdのProduct DescriptionからMSVC/MinGWを判定
    Returns: "MSVC", "MinGW", or None
    """
    has_rich_header, product_descriptions = get_comp_id_info()

    # Rich Headerがない場合、MinGWを返す
    if not has_rich_header or not product_descriptions:
        return "MinGW"

    # Rich Headerがある場合、VS + 4桁数字のフォーマットをチェック
    # 例: "Linker from VS2015", "VS2019", "VS2022" など
    vs_pattern = re.compile(r"VS\d{4}", re.IGNORECASE)

    for desc in product_descriptions:
        # VS + 4桁数字のパターンを検索
        if vs_pattern.search(desc):
            return "MSVC"

    # VS + 4桁数字のパターンが見つからない場合、Noneを返す
    return None


def ask_target_triple():
    """
    Ask user to select target triple (OS and ABI, without architecture)
    CompIdのProduct Descriptionを使ってMSVC/MinGWを自動検出
    """
    try:
        from java.util import ArrayList

        # First ask for OS
        os_choices = ArrayList()
        os_choices.add("Windows")
        os_choices.add("Linux")
        os_choices.add("macOS (Darwin)")
        os_choices.add("Other")
        os_choice = str(
            askChoice("OS Selection", "Select Operating System:", os_choices, "Windows")
        )

        if os_choice == "Windows":
            # CompIdからMSVC/MinGWを自動検出
            detected_abi = detect_msvc_mingw_from_comp_id()

            if detected_abi:
                print("Detected Windows Compiler Type from CompId: " + detected_abi)
                # CompId情報を表示
                has_rich_header, product_descriptions = get_comp_id_info()
                if product_descriptions:
                    print("CompId Product Descriptions:")
                    for desc in product_descriptions:
                        print("  - " + desc)

                # 検出結果を確認
                confirm_msg = "Detected Windows Compiler Type: {}\n\nUse this detection? (Yes to use, No to select manually)".format(
                    detected_abi
                )
                try:
                    use_detected = askYesNo("Compiler Type Detection", confirm_msg)
                except:
                    # askYesNoが利用できない場合、直接選択に進む
                    use_detected = False

                if use_detected:
                    if detected_abi == "MSVC":
                        return "pc-windows-msvc"
                    elif detected_abi == "MinGW":
                        return "pc-windows-gnu"

            # 自動検出が失敗したか、ユーザーが手動選択を選んだ場合
            abi_choices = ArrayList()
            abi_choices.add("MSVC")
            abi_choices.add("MinGW")
            default_choice = detected_abi if detected_abi else "MSVC"
            abi_choice = str(
                askChoice(
                    "Windows Compiler Type Selection",
                    "Select Windows Compiler Type:",
                    abi_choices,
                    default_choice,
                )
            )
            if abi_choice == "MSVC":
                return "pc-windows-msvc"
            elif abi_choice == "MinGW":
                return "pc-windows-gnu"
            else:
                return None
        elif os_choice == "Linux":
            return "unknown-linux-gnu"
        elif os_choice == "macOS (Darwin)":
            return "apple-darwin"
        elif os_choice == "Other":
            # Ask user to enter custom target triple
            custom_triple = askString(
                "Custom Target Triple",
                "Enter target triple (without architecture):",
                "",
            )
            if custom_triple:
                return custom_triple.strip()
            return None
        else:
            return None

    except CancelledException:
        print("User cancelled target triple selection. Exiting...")
        return None
    except Exception as e:
        print("Error asking for target triple: " + str(e))
        return None


def get_rust_version_from_json(commit_hash):
    """
    Get Rust version from rustc_hashes.json using commit hash.
    Returns the rust_version if found, None otherwise.
    """
    if not commit_hash:
        return None

    try:
        # Check if file exists
        if not os.path.exists(RUSTC_HASHES_PATH):
            print(f"Warning: rustc_hashes.json not found at {RUSTC_HASHES_PATH}")
            return None

        # Read JSON file
        with open(RUSTC_HASHES_PATH, "r", encoding="utf-8") as f:
            json_data = json.load(f)

        if isinstance(json_data, dict):
            hash_data = json_data.get("exact_hash_to_version") or []
            rustc_hashes = json_data.get("rustc_hashes") or []
        elif isinstance(json_data, list):
            # Fallback for legacy format where the root is already a list of hashes
            hash_data = []
            rustc_hashes = json_data
        else:
            hash_data = []
            rustc_hashes = []

        # Normalize commit hash to lowercase for comparison
        commit_hash_lower = commit_hash.lower()

        # Search for matching commit hash in exact_hash_to_version entries
        for entry in hash_data:
            entry_hash = (entry.get("commit_hash") or "").lower()
            if entry_hash == commit_hash_lower:
                rust_version = entry.get("rust_version")
                if rust_version:
                    print(f"Found version in rustc_hashes.json: {rust_version}")
                    return rust_version

        # Fallback to rustc_hashes entries which contain richer metadata
        def channel_priority(name):
            lower_name = (name or "").lower()
            if "stable" in lower_name:
                return 0
            if "beta" in lower_name:
                return 1
            if "nightly" in lower_name:
                return 2
            return 3

        def ts_sort_key(entry):
            ts = entry.get("ts")
            if isinstance(ts, str):
                parts = ts.split("-")
                if len(parts) == 3 and all(p.isdigit() for p in parts):
                    year, month, day = map(int, parts)
                    # Use negative values so that newer timestamps come first
                    return (-year, -month, -day)
            return (0, 0, 0)

        matching_entries = [
            entry
            for entry in rustc_hashes
            if (entry.get("git_commit_hash") or "").lower() == commit_hash_lower
        ]

        if matching_entries:
            matching_entries.sort(
                key=lambda entry: (channel_priority(entry.get("channel_name")), ts_sort_key(entry))
            )

            best_entry = matching_entries[0]
            rust_version = best_entry.get("version") or best_entry.get("version_short")

            if rust_version:
                channel_name = best_entry.get("channel_name")
                if channel_name:
                    print(
                        f"Found version in rustc_hashes.json ({channel_name}): {rust_version}"
                    )
                else:
                    print(f"Found version in rustc_hashes.json: {rust_version}")
                return rust_version

        # Not found in JSON
        return None

    except FileNotFoundError:
        print(f"Error: rustc_hashes.json not found at {RUSTC_HASHES_PATH}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse rustc_hashes.json: {str(e)}")
        return None
    except Exception as e:
        print(f"Error reading rustc_hashes.json: {str(e)}")
        return None


def get_rust_version_from_commit(commit_hash):
    """
    Get src/version from Rust repository using GitHub API for specific commit
    """
    url = (
        "https://api.github.com/repos/rust-lang/rust/contents/src/version?ref="
        + commit_hash
    )

    try:
        response = urlopen(url)
        data = json.loads(response.read())

        # Decode Base64 and get text content
        content = base64.b64decode(data["content"]).decode("utf-8").strip()
        return content

    except Exception as e:
        print("Error: " + str(e))
        return None


def get_commit_hash_from_version(version):
    """
    Get commit hash for a specific version by searching through all tags
    """
    url = "https://api.github.com/repos/rust-lang/rust/tags"

    try:
        response = urlopen(url)
        data = json.loads(response.read())

        # Search for the version in tags
        for tag in data:
            if tag["name"] == version:
                commit_hash = tag["commit"]["sha"]
                return commit_hash

        return None

    except Exception as e:
        print("Error getting tags: " + str(e))
        return None


def get_nightly_version(commit_hash):
    """
    Get commit date for a specific commit hash
    """
    url = "https://api.github.com/repos/rust-lang/rust/commits/" + commit_hash

    try:
        response = urlopen(url)
        data = json.loads(response.read())

        # Get commit date and format as nightly-YYYY-MM-DD
        commit_date = data["commit"]["committer"]["date"]
        # Parse ISO date format: 2023-12-07T12:34:56Z
        date_part = commit_date.split("T")[0]  # Get YYYY-MM-DD part
        nightly_version = "nightly-" + date_part

        print("Commit date: " + commit_date)
        print("Nightly version: " + nightly_version)
        return nightly_version

    except Exception as e:
        print("Error getting commit date: " + str(e))
        return None


def main():
    """
    Extract crates and commit hash from Rust binary strings
    """
    print("Extracting crates and commit hash from program: " + currentProgram.getName())
    print("=" * 60)

    # Create iterator for all defined strings in the program
    string_iterator = DefinedStringIterator.forProgram(currentProgram)

    string_count = 0
    all_strings = []

    # Collect all strings first
    while string_iterator.hasNext():
        # Check if user cancelled the operation
        if monitor.isCancelled():
            break

        data = string_iterator.next()

        # Get string information
        address = data.getAddress()
        string_value = data.getValue()
        data_type = data.getDataType().getName()
        length = data.getLength()

        if string_value:
            all_strings.append(string_value)

        string_count += 1

        # Update progress
        if string_count % 100 == 0:
            monitor.setMessage("Processed %d strings..." % string_count)

    print("Total strings processed: %d" % string_count)
    print("=" * 60)

    # Extract crates
    print("Extracting crates...")
    crates = get_crates(all_strings)
    if crates:
        print("Found crates:")
        for crate in sorted(crates):
            print("  - %s" % crate)
    else:
        print("No crates found")

    print("-" * 40)

    # Extract commit hash
    print("Extracting commit hash...")
    commit_hash = get_commithash(all_strings)
    if commit_hash:
        print("Found commit hash: %s" % commit_hash)

        # First, try to get version from rustc_hashes.json
        version = get_rust_version_from_json(commit_hash)

        if version:
            # Version found in JSON, use it directly
            print("Verdict: " + version)
        else:
            # Not found in JSON, fall back to GitHub API
            print("Version not found in rustc_hashes.json, trying GitHub API...")
            version = get_rust_version_from_commit(commit_hash)

            if version:
                # Get commit hash from version using tags endpoint
                tag_commit_hash = get_commit_hash_from_version(version)

                if tag_commit_hash:
                    if commit_hash.lower() == tag_commit_hash.lower():
                        print("Verdict: " + version)
                    else:
                        nightly_version = get_nightly_version(commit_hash)
                        if nightly_version:
                            print("Verdict: " + nightly_version)
                        else:
                            print("Verdict: Could not determine version")
                else:
                    nightly_version = get_nightly_version(commit_hash)
                    if nightly_version:
                        print("Verdict: " + nightly_version)
                    else:
                        print("Verdict: Could not determine version")
            else:
                # GitHub API also failed
                print("Verdict: Could not determine version (GitHub API failed)")
    else:
        print("No commit hash found")

    # Get target triple and architecture from user
    print("-" * 40)
    print("Detecting architecture from program...")

    # Try to automatically detect architecture
    arch = detect_arch()

    # If auto-detection failed, fall back to manual selection
    if arch is None:
        print("Please provide architecture information...")
        arch = ask_arch()
        if arch is None:
            print("=" * 60)
            print("Program cancelled by user")
            return

    # Ask user for target triple
    target_triple = ask_target_triple()
    if target_triple is None:
        print("=" * 60)
        print("Program cancelled by user")
        return

    print("Architecture: %s" % arch)
    print("Target triple (without arch): %s" % target_triple)

    # Build JSON output
    output_data = {
        "commithash": commit_hash if commit_hash else None,
        "target_triple": target_triple if target_triple else None,
        "arch": arch if arch else None,
        "crates": sorted(crates) if crates else [],
    }

    # Save JSON file using askFile dialog
    try:
        # Use askFile to get save location from user
        output_file = askFile("Save JSON output", "Save")
        if output_file is None:
            print("=" * 60)
            print("File save cancelled by user. Exiting...")
            return

        output_filename = output_file.toString()

        # Ensure .json extension
        if not output_filename.lower().endswith(".json"):
            output_filename = output_filename + ".json"

        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        print("=" * 60)
        print("JSON output saved to: %s" % output_filename)
    except CancelledException:
        print("=" * 60)
        print("File save cancelled by user. Exiting...")
        return
    except Exception as e:
        print("Error saving JSON file: " + str(e))
        return

    print("=" * 60)
    print("Analysis complete!")


if __name__ == "__main__":
    main()
