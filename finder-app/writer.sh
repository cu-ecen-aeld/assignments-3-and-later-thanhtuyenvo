#!/bin/bash

FILENAME=''
SEARCHSTR=''

if [ $# -lt 2 ]
then
	echo "use $0 filename string"
	exit 1
else
	FILENAME=$1
	SEARCHSTR=$2
fi

echo ${SEARCHSTR} > ${FILENAME}


