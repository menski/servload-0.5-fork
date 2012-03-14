#!/bin/sh

COMUNITY="ib"

if [[ $# -eq 0 ]]; then
   echo "Usage: $0 host" 
   exit 1
fi

HOST=$1
CPU="?" # gnuplot: set missing
LOAD="?"
MEMORY="?"
SWAP="?"
PROCESSES="?"
TCPESTABLISH="?"
INBYTES="?"
OUTBYTES="?"

result=`snmptable -v 1 -c $COMUNITY -CH $HOST HOST-RESOURCES-MIB::hrProcessorTable`
if [[ $? -eq 0 ]]; then
    CPU=`echo "$result" | awk '{ s += $2 } END { print s / NR }'`
fi

result=`snmptable -v 1 -c $COMUNITY -CH $HOST UCD-SNMP-MIB::laTable`
if [[ $? -eq 0 ]]; then
    LOAD=`echo "$result" | fgrep 'Load-1 ' | awk '{ print $6 }'`
fi

result=`snmpget -v 1 -c $COMUNITY -Oq $HOST UCD-SNMP-MIB::memTotalReal.0 UCD-SNMP-MIB::memAvailReal.0`
if [[ $? -eq 0 ]]; then
    MEMORY=`echo "$result" | paste -s | awk '{ if ($4 > 0) { if ($2 > 0) { print (($2 - $4) / $2) * 100 } else { print 100 } } else { print 0 } }'`
fi

result=`snmpget -v 1 -c $COMUNITY -Oq $HOST UCD-SNMP-MIB::memTotalSwap.0 UCD-SNMP-MIB::memAvailSwap.0`
if [[ $? -eq 0 ]]; then
    SWAP=`echo "$result" | paste -s | awk '{ if ($4 > 0) { if ($2 > 0) { print (($2 - $4) / $2) * 100 } else { print 100 } } else { print 0 } }'`
fi

result=`snmpget -v 1 -c $COMUNITY -Oq $HOST HOST-RESOURCES-MIB::hrSystemProcesses.0`
if [[ $? -eq 0 ]]; then
    PROCESSES=`echo "$result" | awk '{ print $2 }'`
fi

result=`snmpget -v 1 -c $COMUNITY -Oq $HOST TCP-MIB::tcpCurrEstab.0`
if [[ $? -eq 0 ]]; then
    TCPESTABLISH=`echo "$result" | awk '{ print $2 }'`
fi

[ -f $HOST.snmp.tmp ] && . $HOST.snmp.tmp
result=`snmpnetstat -v 1 -c $COMUNITY -Co -Ci $HOST`
if [[ $? -eq 0 ]]; then
    in=`echo "$result" | sed '1d' | awk '{ s += $5 } END { print s }'`
    out=`echo "$result" | sed '1d' | awk '{ s += $6 } END { print s }'`
    [ -n "$inprevious" ] && INBYTES=`expr $in - $inprevious` 
    [ -n "$outprevious" ] && OUTBYTES=`expr $out - $outprevious`
    echo "inprevious=$in" > $HOST.snmp.tmp
    echo "outprevious=$out" >> $HOST.snmp.tmp
fi

# gnuplot style
echo "CPU% $CPU Load# $LOAD Memory% $MEMORY Swap% $SWAP Processes# $PROCESSES TCPEstablish# $TCPESTABLISH InBytes $INBYTES OutBytes $OUTBYTES" >> $HOST.snmp.dat
