
List all thorough_tests property enabled nessus plugins:
```
[root@tenable-5cfxx56r nasl]# cat /root/plugin-filter.sh 
#!/bin/bash


for f in $(ls -1 |xargs grep -l '"thorough_tests", value:"true"'); do 
        grep script_id $f | sed 's/.(\(.\))/\1/' |tr -d ';'
done

[root@tenable-5cfxx56r nasl]# time (/root/plugin-filter.sh  > /root/plugin2.lst)

real    0m28.332s
user    0m7.126s
sys     0m21.260s
[root@tenable-5cfxx56r nasl]# 

[root@tenable-5cfxx56r nasl]# wc -l /root/plugin2.lst 
6064 /root/plugin2.lst
```
