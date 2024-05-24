import argparse
import time
import sys
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from subhawk.constants import INFO, VULN, ERROR, WORK, DEBUG
from subhawk.subhawk import takeover
from subhawk.utils import generate_resumecfg, resume, save_result, extract_domain, format_time, print_logs


def main(targets):
    try:
        start_time = time.time()
        total_targets = len(targets)

        with Progress(
            SpinnerColumn("pipe", style="yellow"), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task(f"{WORK} 0/{total_targets}", total=total_targets)
            console.print(f"{INFO} Loaded {len(targets)} targets.")
            for count, target in enumerate(targets, start=1):
                if args.verbose:
                    console.print(f"{INFO} Testing: {target}")
                result = takeover(target)
                if result:
                    target = extract_domain(target, True)
                    progress.print(f"{VULN} {target}")
                    save_result(target, args.output)
                progress.update(task, advance=1, description=f"{WORK} {count}/{total_targets}")

        console.print(f"{DEBUG} Tested {total_targets} targets in {format_time(time.time() - start_time)}.")
        print_logs()

    except KeyboardInterrupt:
        generate_resumecfg(target)
        console.print(f"{ERROR} Progress saved to resume.cfg.")
        print_logs()

    except Exception as e:
        console.print(f"{ERROR}: {e}")
        generate_resumecfg(target)
        print_logs()


if __name__ == '__main__':
    console = Console()
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list", required=True, help="Path to the file containing list of Domains/URLs.")
    parser.add_argument("-o", "--output", required=False, help="Path to the file to save the results.")
    parser.add_argument("-r", "--resume", required=False, help="Path to the resume configuration file.")
    parser.add_argument("-v", "--verbose", action='store_true',required=False, help="Verbose mode.")

    args = parser.parse_args()

    targets = []
    if args.resume:
        resume_from = resume(args.resume)
        if resume_from is not None:
            with open(args.list, 'r') as file:
                targets = file.read().splitlines()
                try:
                    targets = targets[targets.index(resume_from):]
                except ValueError:
                    console.print(f"{ERROR} cannot resume from {resume_from} because it's not found in {args.list}.")
                    sys.exit(1)
        else:
            console.print(f"{ERROR} Unsupported resume file.")
            sys.exit(1)
    else:
        try:
            with open(args.list, 'r') as file:
                targets = file.read().splitlines()
        except FileNotFoundError:
            console.print(f"{ERROR} File not found.")
            sys.exit(1)

    main(targets)
