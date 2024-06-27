#!/bin/sh

module="aesdchar"
device="aesdchar"
mode="664"
group="staff"

set -e

case "$1" in
    start)
        cd /lib/modules/$(uname -r)/extra
        insmod ./${module}.ko || exit 1
        major=$(awk "\$2==\"$module\" {print \$1}" /proc/devices)
        if [ ! -z ${major} ]; then
            echo "Remove any existing /dev node for /dev/${device}"
            rm -f /dev/${device}
            mknod /dev/${device} c $major 0
            chgrp $group /dev/${device}
            chmod $mode  /dev/${device}
        else
            echo "No device found in /proc/devices for driver ${module} (this driver may not allocate a device)"
        fi
        ;;
    stop)
        rmmod ${module} || exit 1
        rm -f /dev/${device}
        ;;
    *)
        echo "Usage: $0 {start | stop}"
        exit 1
esac
exit 0
