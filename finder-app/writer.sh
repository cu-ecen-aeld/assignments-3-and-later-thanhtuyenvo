#!/bin/bash

writefile=$1
writestr=$2

if [ $# -ne 2 ];
then
    #Check if we have enough 2 arguments as input
    echo "ERROR: Invalid Number of Arguments."
    echo "Total number of arguments should be 2."
    exit 1
fi

if [ ! -d ${writefile%/*} ];
then
    #If file does not exist, created this file
    mkdir -p "${writefile%/*}"
fi

if ! echo $writestr > $writefile;
then
    #Write to file if file exist
    echo "ERROR: file cannot be created"
    exit 1

fi


