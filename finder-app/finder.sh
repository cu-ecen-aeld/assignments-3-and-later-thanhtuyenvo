#!/bin/bash
# Define two variables for file directory and the string that we need to search
FILESDIR=''
SEARCHSTR=''


if [ $# -lt 2 ]
then
	# If number of arguments passing to this shell is less than 2, it means that
	# there is a parameter that was not specified
	echo "use $0 dir search_string"
	exit 1
else
	#get values from 2 parameters
	FILESDIR=$1
	SEARCHSTR=$2
fi

if ! [ -d ${FILESDIR}  ]
then	
	# This directory does not exist
	echo "${FILESDIR} does not exist."
	exit 1
fi
NUM_FINDINGS=$(grep -l "$SEARCHSTR" ${FILESDIR}/* 2>/dev/null| wc -l)
TOTAL_FILES=$(ls -p ${FILESDIR}| grep -v / | wc -l)

echo "The number of files are ${TOTAL_FILES} and the number of matching lines are ${NUM_FINDINGS}"
