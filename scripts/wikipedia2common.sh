#!/bin/sh

MINUTES="60*10"

if [[ $# -eq 0 ]]; then
   echo "Usage: $0 logfile"
   exit 1
fi

LOGFILE=$1

# unzip and sort
gunzip -c $LOGFILE.gz > $LOGFILE
sort -n -k2 $LOGFILE > $LOGFILE.sort

# cut until minutes
START=`head -n1 $LOGFILE.sort | cut -f2 -d' '`
END=`echo "$MINUTES + $START" | bc`
awk '{if ($2 <= '"$END"') print $0;}' $LOGFILE.sort > $LOGFILE.minutes
rm $LOGFILE.sort

# filter only english and image requests
FILTER="http://en\.wikipedia\.org|http://upload\.wikimedia\.org/wikipedia/commons/|http://upload\.wikimedia\.org/wikipedia/en/"
egrep $FILTER $LOGFILE.minutes > $LOGFILE.filter
rm $LOGFILE.minutes

# rewrite url and image requests
REWRITE1="s/http:\/\/en\.wikipedia\.org\/wiki\//\/wiki\//"
REWRITE2="s/http:\/\/en\.wikipedia\.org\/w\//\/w\//"
REWRITE3="s/http:\/\/en\.wikipedia\.org\//\/w\//"
REWRITE4="s/http:\/\/upload\.wikimedia\.org\/wikipedia\/commons\//\/w\/images\//"
REWRITE5="s/http:\/\/upload\.wikimedia\.org\/wikipedia\/en\//\/w\/images\//"

# convert to common log
rm $LOGFILE.log
while read USERID TIMESTAMP URL SAVE; do
    if [ $SAVE = "-" ]; then
        DATE=`date -d @$TIMESTAMP +"[%d/%b/%Y:%H:%M:%S.%N %z]"`
        RURL=`echo "$URL" | sed -e $REWRITE1 -e $REWRITE2 -e $REWRITE3 -e $REWRITE4 -e $REWRITE5`
        echo "www.salbnet.org - $USERID $DATE \"GET $RURL HTTP/1.1\" 200 -" >> $LOGFILE.log
    fi
done < $LOGFILE.filter
#rm $LOGFILE.filter

