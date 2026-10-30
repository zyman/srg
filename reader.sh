#!/bin/sh
# Shared forced command for Linux and QNAP. No caller-supplied shell or paths.
set -eu
export LC_ALL=C
case "${SSH_ORIGINAL_COMMAND-}" in
  health) ;;
  *) exit 64 ;;
esac
exec awk '
 FILENAME == "/proc/uptime" { uptime=$1 }
 FILENAME == "/proc/loadavg" { l1=$1; l5=$2; l15=$3 }
 FILENAME == "/proc/meminfo" && $1 == "MemTotal:" { total=$2 }
 FILENAME == "/proc/meminfo" && $1 == "MemAvailable:" { available=$2; has_available=1 }
 FILENAME == "/proc/meminfo" && $1 == "MemFree:" { free=$2 }
 FILENAME == "/proc/meminfo" && $1 == "Buffers:" { buffers=$2 }
 FILENAME == "/proc/meminfo" && $1 == "Cached:" { cached=$2 }
 END {
  if (total <= 0 || uptime <= 0) exit 65;
  if (!has_available) available=free+buffers+cached;
  printf "{\"uptime_seconds\":%.2f,\"load_average\":[%.2f,%.2f,%.2f],\"memory_total_kib\":%.0f,\"memory_available_kib\":%.0f,\"memory_available_estimated\":%s}\n", uptime,l1,l5,l15,total,available,has_available?"false":"true";
 }' /proc/uptime /proc/loadavg /proc/meminfo
