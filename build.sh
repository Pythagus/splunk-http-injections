#!/bin/bash
#
# This script builds the app's TarGZ file used to
# update the application's code in SplunkBase.
#
# Author: Damien MOLINA
# 
# 2024-08-29: First version of the script
# 2024-09-16: Rename the app

# The file name of the generated application.
OUTPUT_FILE=http-injections-app.tar.gz

# If the output file already exists, then
# delete it to generate a new one.
if [ -f $OUTPUT_FILE ] ; then
    rm $OUTPUT_FILE
fi

# Generate the new export.
COPYFILE_DISABLE=1 tar \
    --exclude-vcs \
    --exclude="__pycache__" \
    --exclude="log" \
    --format ustar \
    -cvzf \
    $OUTPUT_FILE http-injections-app