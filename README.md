# Analyze Attacks

Analyze Attacks is an advanced log analysis tool that helps system administrators detect malicious traffic against popular web hosting stacks. It supports environments such as RunCloud, Plesk, cPanel, Apache, and Nginx, and focuses on identifying suspicious activity quickly so you can respond before an incident escalates.

## Version

* **Current release:** 0.92 beta (English)
* **Author:** David Carrero Fernández-Baillo (<dcarrero@stackscale.com>)
* **License:** MIT

## Key Features

* Detects abusive or suspicious IP addresses in web server access logs.
* Highlights malicious bot activity, WordPress attacks, suspicious 404 responses, SQL injection/XSS attempts, and more.
* Supports IPv4 and IPv6 log formats with customizable thresholds and time windows.
* Automatically searches common locations for both access and error logs across major hosting panels.
* Offers optional log saving with ANSI color stripping for clean text output.

## Requirements

* Bash 4.x or later
* Standard GNU/Linux userland tools (`awk`, `sed`, `grep`, `find`, etc.)
* Read access to your web server log files (access and, optionally, error logs)

No additional dependencies or Python/Ruby runtimes are required.

## Getting Started

1. Clone or download this repository onto the target server.
2. Make the script executable:
   ```bash
   chmod +x analyze_attacks.sh
   ```
3. Run the script with elevated privileges if your log files require them:
   ```bash
   sudo ./analyze_attacks.sh
   ```

On launch, you will see an interactive menu that summarizes the current configuration (log paths, thresholds, and output settings) and lets you choose the type of analysis to perform.

## Command-Line Options

You can override defaults or automate runs by providing command-line flags:

```bash
./analyze_attacks.sh [OPTIONS]
```

| Option | Description |
| ------ | ----------- |
| `--help`, `-h` | Show the built-in help screen. |
| `--minrequest <number>` | Minimum number of requests from an IP before it is highlighted. Default: `20`. |
| `--hoursago <number>` | Time window (in hours) to analyze. Default: `24`. |
| `--logpath <path>` | Custom glob pattern for access logs. Wrap in quotes if it includes wildcards. |
| `--errorlog <path>` | Custom glob pattern for error logs. If omitted, the script attempts autodetection. |
| `--output <filename>` | File name to use when saving results. Default: `analyze_attacks.log`. |
| `--save` | Enable saving the analysis output to the specified file. |

## Example Usage

* Analyze the last 6 hours of access logs and save results:
  ```bash
  ./analyze_attacks.sh --hoursago 6 --save
  ```
* Review only cPanel-style log locations with a higher alert threshold:
  ```bash
  ./analyze_attacks.sh --logpath "/usr/local/apache/domlogs/*access_log*" --minrequest 50
  ```
* Provide a custom error log location for correlation:
  ```bash
  ./analyze_attacks.sh --errorlog "/var/log/nginx/error.log"
  ```

During interactive use, you can press `s` to toggle saving to file, `r` to change access log paths, or `e` to adjust error log paths directly from the menu.

## Output

By default, Analyze Attacks prints colored summaries to the terminal. When `--save` is enabled, the script writes a color-free version to the output file so it can be shared or archived easily. Each menu option produces a different report section tailored to the selected attack pattern.

## Support

If you encounter issues or want to contribute improvements, feel free to open an issue or submit a pull request on this repository.

