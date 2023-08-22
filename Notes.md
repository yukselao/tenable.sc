
List all thorough_tests property enabled nessus plugins:
```
#!/bin/bash

outputfile="$1"

function printusage {
        echo "Usage:"
}

if [ -z "$outputfile" ]; then
        printusage
        exit 1
fi

>$outputfile
>${outputfile}-enriched

(for f in $(ls -1 |xargs grep -l '"thorough_tests", value:"true"'); do grep script_id $f | sed 's/.(\(.\))/\1/' |tr -d ';'; done) &> $outputfile
sed -r -i 's#(script_id|\s|\t|\(|\))##g' $1

#sql="select Plugin.id, Plugin.name, Family.Id, Family.Name from Plugin, Family where Plugin.FamilyId=Family.id and Plugin.id in ( $(cat $outputfile | tr '\n' ','))"
#sqlite3 /opt/sc/plugins.db -header -csv "$sql" > /root/plugins.csv

for pluginid in $(cat $outputfile); do
        sql="select Plugin.id, Plugin.name, Family.Id, Family.Name from Plugin, Family where Plugin.FamilyId=Family.id and Plugin.id=$pluginid"
        out=$(sqlite3 /opt/sc/plugins.db "$sql")
        if [[ $? -eq 0 ]]; then
                echo $out >> ${outputfile}-enriched
        else
                echo $pluginid not found
        fi
done
```
Logs:
```[root@tenable-5cfxx56r nasl]# tail /root/plugin.lst-enriched
35803|zFeeder admin.php Direct Request Admin Authentication Bypass|6|CGI abuses
14325|ZixForum ZixForum.mdb DIrect Request Database Disclosure|6|CGI abuses
168810|Zoom Client for Meetings < 5.12.6 Vulnerability (ZSB-22025)|23|Misc.
174469|Zoom Client for Meetings < 5.13.3 Vulnerability / Zoom VDI < 5.13.1 Information Disclosure (ZSB-23001)|23|Misc.
177232|Zoom Client for Meetings < 5.13.10 Vulnerability (ZSB-23006)|23|Misc.
177234|Zoom Client for Meetings < 5.13.10 Vulnerability (ZSB-23007)|23|Misc.
17312|Zorum <= 3.5 Multiple Remote Vulnerabilities|6|CGI abuses
24698|ZPanel 2.0 Multiple Script Remote File Inclusion|6|CGI abuses
40886|Zmanda Recovery Manager for MySQL socket-server.pl MYSQL_BINPATH Variable Command Execution|6|CGI abuses
78430|ZXShell Malware Services Detection|35|Backdoors
```
