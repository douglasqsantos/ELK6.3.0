# Concepts

- Elasticsearch
  - https://www.elastic.co
- Logstash
- Kibana
- Use Case
- Beats

## Elastic Stack
- User Interface
  - Kibana
- Store, Index & Analyze
  - Elasticsearch
    - (JSON) JavaScript Object Notation
- Ingest
  - Logstash
    - Rsyslog
  - Beats
- X-Pack
  - Security
  - Alerting
  - Monitoring
  - Reporting
  - Graph

## Kibana e Elasticsearch - Installation
- Elasticsearch Installation
- Elasticsearch Configuration
- Kibana Installation
- Kibana Configuration
- Beats Agent Test


## On Ubuntu 18.04
- Elasticsearch
  - https://www.elastic.co/downloads/elasticsearch
  - https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.1.3.deb
  - https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.6.2-amd64.deb
- Kibana
  - https://www.elastic.co/downloads/kibana
  - https://artifacts.elastic.co/downloads/kibana/kibana-6.1.3-amd64.deb
  - https://artifacts.elastic.co/downloads/kibana/kibana-7.6.2-amd64.deb


Installing the dependencies
```bash
apt-get install openjdk-8-jre -y
```

Elasticsearch installation
```bash
dpkg -i elasticsearch-6.1.3.deb
```

Elasticsearch's configuration files
```
ls -l /etc/elasticsearch/
total 16
-rw-rw---- 1 root elasticsearch 2869 Jan 26  2018 elasticsearch.yml
-rw-rw---- 1 root elasticsearch 2678 Jan 26  2018 jvm.options
-rw-rw---- 1 root elasticsearch 5091 Jan 26  2018 log4j2.properties
```

Configure where the Elastic search will bind
```bash
vim /etc/elasticsearch/elasticsearch.yml
[...]
network.host: 192.168.0.30
```

Installing Kibana from the deb package
```bash
dpkg -i kibana-6.1.3-amd64.deb
```

Kibana's Configuration files
```bash
ls -l /etc/kibana/
total 8
-rw-r--r-- 1 root root 4645 Jan 26  2018 kibana.yml
```

Configuring the Elasticsearch access from Kibana
```
vim /etc/kibana/kibana.yaml
[...]
server.host: "192.168.0.30"
[...]
# The URL of the Elasticsearch instance to use for all your queries.
elasticsearch.url: "http://192.168.0.30:9200"
```

Restarting the service elasticsearch and kibana
```bash
systemctl restart elasticsearch
systemctl restart kibana
```

Check the Elastic and Kibana status
```bash
systemctl status elasticsearch kibana -l
● elasticsearch.service - Elasticsearch
   Loaded: loaded (/usr/lib/systemd/system/elasticsearch.service; disabled; vendor preset: enabled)
   Active: active (running) since Thu 2020-05-07 11:37:32 -03; 8s ago
     Docs: http://www.elastic.co
 Main PID: 5536 (java)
    Tasks: 36 (limit: 2321)
   CGroup: /system.slice/elasticsearch.service
           └─5536 /usr/bin/java -Xms1g -Xmx1g -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=75 -XX:+UseCMSInitiatingOccupancyOnly -XX:+AlwaysPreTouch -server -Xss1m

May 07 11:37:32 ubuntu18lts systemd[1]: Started Elasticsearch.

● kibana.service - Kibana
   Loaded: loaded (/etc/systemd/system/kibana.service; disabled; vendor preset: enabled)
   Active: active (running) since Thu 2020-05-07 11:37:37 -03; 3s ago
 Main PID: 5606 (node)
    Tasks: 6 (limit: 2321)
   CGroup: /system.slice/kibana.service
           └─5606 /usr/share/kibana/bin/../node/bin/node --no-warnings /usr/share/kibana/bin/../src/cli -c /etc/kibana/kibana.yml

May 07 11:37:37 ubuntu18lts systemd[1]: Started Kibana.
```

Double check Elastic search log file
```bash
tail -f /var/log/elasticsearch/elastic
elastic.log                         elastic_deprecation.log             elastic_index_indexing_slowlog.log  elastic_index_search_slowlog.log
root@ubuntu18lts:~# tail -f /var/log/elasticsearch/elastic.log
[2020-05-07T11:37:38,313][INFO ][o.e.d.DiscoveryModule    ] [master] using discovery type [zen]
[2020-05-07T11:37:39,642][INFO ][o.e.n.Node               ] [master] initialized
[2020-05-07T11:37:39,642][INFO ][o.e.n.Node               ] [master] starting ...
[2020-05-07T11:37:39,893][INFO ][o.e.t.TransportService   ] [master] publish_address {192.168.0.30:9300}, bound_addresses {192.168.0.30:9300}
[2020-05-07T11:37:39,908][INFO ][o.e.b.BootstrapChecks    ] [master] bound or publishing to a non-loopback address, enforcing bootstrap checks
[2020-05-07T11:37:43,052][INFO ][o.e.c.s.MasterService    ] [master] zen-disco-elected-as-master ([0] nodes joined), reason: new_master {master}{A5A9kbqxTgahhSmz0gUZEA}{8J0tVV4BTjmt0OMNSDJPYA}{192.168.0.30}{192.168.0.30:9300}
[2020-05-07T11:37:43,079][INFO ][o.e.c.s.ClusterApplierService] [master] new_master {master}{A5A9kbqxTgahhSmz0gUZEA}{8J0tVV4BTjmt0OMNSDJPYA}{192.168.0.30}{192.168.0.30:9300}, reason: apply cluster state (from master [master {master}{A5A9kbqxTgahhSmz0gUZEA}{8J0tVV4BTjmt0OMNSDJPYA}{192.168.0.30}{192.168.0.30:9300} committed version [1] source [zen-disco-elected-as-master ([0] nodes joined)]])
[2020-05-07T11:37:43,132][INFO ][o.e.h.n.Netty4HttpServerTransport] [master] publish_address {192.168.0.30:9200}, bound_addresses {192.168.0.30:9200}
[2020-05-07T11:37:43,137][INFO ][o.e.n.Node               ] [master] started
[2020-05-07T11:37:43,147][INFO ][o.e.g.GatewayService     ] [master] recovered [0] indices into cluster_state
```

Double check other logs
- /var/log/syslog
- /var/log/messages


Kibana url access: http://192.168.0.30:5601

## Agent Beats
- https://www.elastic.co/downloads/beats
- https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.1.3-amd64.deb
- https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.6.2-amd64.deb

Installing the Filebeat
```bash
dpkg -i filebeat-6.1.3-amd64.deb
```

Filebeat basic configuration
```bash
vim /etc/filebeat/filebeat.yml
[...]
- type: log

  # Change to true to enable this prospector configuration.
  enabled: true

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    - /var/log/auth.log
[...]
# Exclude files. A list of regular expressions to match. Filebeat drops the files that
  # are matching any regular expression from the list. By default, no files are dropped.
  exclude_files: ['.gz$']
[...]
# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  host: "192.168.0.30:5601"
[...]
#-------------------------- Elasticsearch output ------------------------------
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["192.168.0.30:9200"]
```

Restart the Filebeat Daemon
```bash
systemctl restart filebeat
```

Check the status of the Filebeat
```bash
systemctl status filebeat
● filebeat.service - filebeat
   Loaded: loaded (/lib/systemd/system/filebeat.service; disabled; vendor preset: enabled)
   Active: active (running) since Thu 2020-05-07 11:55:53 -03; 44s ago
     Docs: https://www.elastic.co/guide/en/beats/filebeat/current/index.html
 Main PID: 5990 (filebeat)
    Tasks: 9 (limit: 2321)
   CGroup: /system.slice/filebeat.service
           └─5990 /usr/share/filebeat/bin/filebeat -c /etc/filebeat/filebeat.yml -path.home /usr/share/filebeat -path.config /etc/filebeat -path.data /var/lib/filebeat -path.logs

May 07 11:55:53 ubuntu18lts systemd[1]: Started filebeat.
```

Double check the Filebeat log file
```bash
tail -f /var/log/filebeat/filebeat
2020-05-07T11:55:53-03:00 INFO Starting Registrar
2020-05-07T11:55:53-03:00 INFO Config reloader started
2020-05-07T11:55:53-03:00 INFO Loading of config files completed.
2020-05-07T11:55:53-03:00 INFO Harvester started for file: /var/log/auth.log
2020-05-07T11:55:54-03:00 INFO Connected to Elasticsearch version 6.1.3
2020-05-07T11:55:54-03:00 INFO Loading template for Elasticsearch version: 6.1.3
2020-05-07T11:55:54-03:00 INFO Elasticsearch template with name 'filebeat-6.1.3' loaded
2020-05-07T11:56:23-03:00 INFO Non-zero metrics in the last 30s: beat.info.uptime.ms=30005 beat.memstats.gc_next=4194304 beat.memstats.memory_alloc=3212904 beat.memstats.memory_total=6841112 filebeat.events.added=70 filebeat.events.done=70 filebeat.harvester.open_files=1 filebeat.harvester.running=1 filebeat.harvester.started=1 libbeat.config.module.running=0 libbeat.config.reloads=1 libbeat.output.read.bytes=1731 libbeat.output.type=elasticsearch libbeat.output.write.bytes=37522 libbeat.pipeline.clients=1 libbeat.pipeline.events.active=0 libbeat.pipeline.events.filtered=1 libbeat.pipeline.events.published=69 libbeat.pipeline.events.retry=50 libbeat.pipeline.events.total=70 libbeat.pipeline.queue.acked=69 registrar.states.current=1 registrar.states.update=70 registrar.writes=4
2020-05-07T11:56:53-03:00 INFO Non-zero metrics in the last 30s: beat.info.uptime.ms=30000 beat.memstats.gc_next=4194304 beat.memstats.memory_alloc=3245832 beat.memstats.memory_total=6874040 filebeat.harvester.open_files=1 filebeat.harvester.running=1 libbeat.config.module.running=0 libbeat.pipeline.clients=1 libbeat.pipeline.events.active=0 registrar.states.current=1
2020-05-07T11:57:23-03:00 INFO Non-zero metrics in the last 30s: beat.info.uptime.ms=29999 beat.memstats.gc_next=4194304 beat.memstats.memory_alloc=3261400 beat.memstats.memory_total=6889608 filebeat.harvester.open_files=1 filebeat.harvester.running=1 libbeat.config.module.running=0 libbeat.pipeline.clients=1 libbeat.pipeline.events.active=0 registrar.states.current=1
```

Now open a new ssh connection and let's take a look at the elasticsearch log file 
```bash
tail -f /var/log/elasticsearch/elastic.log
[2020-05-07T11:37:39,642][INFO ][o.e.n.Node               ] [master] initialized
[2020-05-07T11:37:39,642][INFO ][o.e.n.Node               ] [master] starting ...
[2020-05-07T11:37:39,893][INFO ][o.e.t.TransportService   ] [master] publish_address {192.168.0.30:9300}, bound_addresses {192.168.0.30:9300}
[2020-05-07T11:37:39,908][INFO ][o.e.b.BootstrapChecks    ] [master] bound or publishing to a non-loopback address, enforcing bootstrap checks
[2020-05-07T11:37:43,052][INFO ][o.e.c.s.MasterService    ] [master] zen-disco-elected-as-master ([0] nodes joined), reason: new_master {master}{A5A9kbqxTgahhSmz0gUZEA}{8J0tVV4BTjmt0OMNSDJPYA}{192.168.0.30}{192.168.0.30:9300}
[2020-05-07T11:37:43,079][INFO ][o.e.c.s.ClusterApplierService] [master] new_master {master}{A5A9kbqxTgahhSmz0gUZEA}{8J0tVV4BTjmt0OMNSDJPYA}{192.168.0.30}{192.168.0.30:9300}, reason: apply cluster state (from master [master {master}{A5A9kbqxTgahhSmz0gUZEA}{8J0tVV4BTjmt0OMNSDJPYA}{192.168.0.30}{192.168.0.30:9300} committed version [1] source [zen-disco-elected-as-master ([0] nodes joined)]])
[2020-05-07T11:37:43,132][INFO ][o.e.h.n.Netty4HttpServerTransport] [master] publish_address {192.168.0.30:9200}, bound_addresses {192.168.0.30:9200}
[2020-05-07T11:37:43,137][INFO ][o.e.n.Node               ] [master] started
[2020-05-07T11:37:43,147][INFO ][o.e.g.GatewayService     ] [master] recovered [0] indices into cluster_state
[2020-05-07T11:55:54,758][INFO ][o.e.c.m.MetaDataCreateIndexService] [master] [filebeat-6.1.3-2020.05.07] creating index, cause [auto(bulk api)], templates [filebeat-6.1.3], shards [3]/[1], mappings [doc]
```

The last line of the file we have a new index

The indexes are store in:
```bash
ls -l /var/lib/elasticsearch/nodes/0/indices/
total 4
drwxr-xr-x 6 elasticsearch elasticsearch 4096 May  7 11:55 mfFn-sKvSWCQCRc0SlC2aw
```

On Kibana interface select
- Management
  - Index Patterns
    - index pattern:
      - filebeat-*
        - Next Step
      - Time Filter field name:L
        - @timestamp
          - Create index pattern

On kibana interface
- Discover


## Elastic Courses
- https://training.elastic.co/learn-from-home?baymax=rtp&elektra=home&storm=sub2&rogue=default&iesrc=ctr

