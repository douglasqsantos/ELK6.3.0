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
  - https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.8.8.deb
  - https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.6.2-amd64.deb
- Kibana
  - https://www.elastic.co/downloads/kibana
  - https://artifacts.elastic.co/downloads/kibana/kibana-6.1.3-amd64.deb
  - https://artifacts.elastic.co/downloads/kibana/kibana-6.8.8-amd64.deb
  - https://artifacts.elastic.co/downloads/kibana/kibana-7.6.2-amd64.deb


Installing the dependencies
```bash
apt-get install openjdk-8-jre -y
```

Elasticsearch installation
```bash
dpkg -i elasticsearch-6.8.8.deb
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
dpkg -i kibana-6.8.8-amd64.deb
```

Kibana's Configuration files
```bash
ls -l /etc/kibana/
total 8
-rw-r--r-- 1 root root 4645 Jan 26  2018 kibana.yml
```

Configuring the Elasticsearch access from Kibana
```yaml
vim /etc/kibana/kibana.yaml
[...]
server.host: "192.168.0.30"
[...]
# The URL of the Elasticsearch instance to use for all your queries.
elasticsearch.url: "http://192.168.0.30:9200"
```

Enabling the service elasticsearch and kibana
```bash
systemctl enable elasticsearch
systemctl enable kibana
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
- https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.1.3-amd64.deb
- https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.6.2-amd64.deb

Installing the Filebeat
```bash
dpkg -i filebeat-6.8.8-amd64.deb
```

Filebeat basic configuration
```yaml
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

Enabling the Filebeat
```bash
systemctl enable filebeat
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
    - create index pattern
    - index pattern:
      - filebeat-*
        - Next Step
      - Time Filter field name:
        - @timestamp
          - Create index pattern

On kibana interface
- Discover

## Logstash
- Installing
  - https://artifacts.elastic.co/downloads/logstash/logstash-6.4.2.deb
  - https://artifacts.elastic.co/downloads/logstash/logstash-7.6.2.deb
- Basic Configuration


Installing the dependencies
```bash
apt-get install openjdk-8-jre -y
```

Instaling the logstash
```bash
dpkg -i logstash-6.4.2.deb
```

Enabling the logstash
```bash
systemctl enable logstash
```

Logstash Basic Configuration 
```bash
vim /etc/logstash/logstash.yml
[...]
```

Logstash pipeline
```bash
vim /etc/logstash/pipelines.yml
```

Lets create the rule on **Kibana/Dev Tools**

On Sample Data use
```bash
May  7 13:33:25 kube-node01 sshd[1370]: Accepted publickey for root from 192.168.0.105 port 60560 ssh2: RSA SHA256:3w7NianF6lkwJbdBZK59l3XFe7fNFYVo2kkU6UWmvwU
```

On Grok Pattern use
```
%{DATA:time} kube-node01 %{WORD:program}\[%{NUMBER:pid:int}\]: %{DATA:msg} for %{DATA:user} from %{IPORHOST:source_ip} port %{NUMBER:port_number} %{WORD:service}: %{WORD:algo} %{GREEDYDATA:publickey}
```

Now select Simulate to check if all the information was correctly parsed

**Some Examples:**
- https://www.elastic.co/blog/grokking-the-linux-authorization-logs
- https://github.com/thomaspatzke/logstash-linux
- https://discuss.elastic.co/t/grokparsefailure-for-auth-log/104127/2
- https://discuss.elastic.co/t/grokking-the-linux-authorization-logs/104467/5
- https://www.elastic.co/guide/en/logstash/current/logstash-config-for-filebeat-modules.html

Now on the server that was install logstash let's create the rule

```bash
vim /etc/logstash/conf.d/auth.conf
input {
  file {
    path => [ "/var/log/auth.log" ]
    type => "secure-log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  if [type] == "secure-log" {
    grok {
      match => { "message" => "%{DATA:time} kube-node01 %{WORD:program}\[%{NUMBER:pid:int}\]: %{DATA:msg} for %{DATA:user} from %{IPORHOST:source_ip} port %{NUMBER:port_number} %{WORD:service}: %{WORD:algo} %{GREEDYDATA:publickey}" }
      match => { "message" => "%{DATA:time} kube-node01 %{WORD:program}\[%{NUMBER:pid:int}\]: %{DATA:msg} for user %{DATA:user} by \(uid=%{NUMBER:uid}\)" }
    }
  }
}

output {
  if [type] == "secure-log" {
    elasticsearch {
      hosts => ["192.168.0.30:9200"]
      index => "secure-%{+YYYY.MM.dd}"
    }
  }
}
```

Now let`s add the logstash to the root group, otherwise the logstash user will not be able to read the auth.log
```bash
usermod -aG root logstash
usermod -aG adm logstash
```

Now we need to restart the logstash
```bash
systemctl restart logstash
```

Check the logstash status
```bash
systemctl status logstash
```

Checking the log file
```bash
tail -f /var/log/logstash/logstash-plain.log
```

On Kibana interface select
- Management
  - Index Patterns
    - create index pattern
    - index pattern:
      - secure-*
        - Next Step
      - Time Filter field name:
        - @timestamp
          - Create index pattern


Another use
```bash
vim /etc/logstash/conf.d/auth.conf
input {
  file {
    path => [ "/var/log/auth.log" ]
    type => "secure-log"
  }
}

filter {
  if [type] == "secure-log" {
    grok {
      match => { "message" => ["%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} for (invalid user )?%{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]} port %{NUMBER:[system][auth][ssh][port]} ssh2(: %{GREEDYDATA:[system][auth][ssh][signature]})?",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} user %{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: Did not receive identification string from %{IPORHOST:[system][auth][ssh][dropped_ip]}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: \s*%{DATA:[system][auth][user]} :( %{DATA:[system][auth][sudo][error]} ;)? TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{DATA:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} groupadd(?:\[%{POSINT:[system][auth][pid]}\])?: new group: name=%{DATA:system.auth.groupadd.name}, GID=%{NUMBER:system.auth.groupadd.gid}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} useradd(?:\[%{POSINT:[system][auth][pid]}\])?: new user: name=%{DATA:[system][auth][user][add][name]}, UID=%{NUMBER:[system][auth][user][add][uid]}, GID=%{NUMBER:[system][auth][user][add][gid]}, home=%{DATA:[system][auth][user][add][home]}, shell=%{DATA:[system][auth][user][add][shell]}$",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} %{DATA:[system][auth][program]}(?:\[%{POSINT:[system][auth][pid]}\])?: %{GREEDYMULTILINE:[system][auth][message]}"] }
      pattern_definitions => {
        "GREEDYMULTILINE"=> "(.|\n)*"
      }
    }
  }
}

output {
  if [type] == "secure-log" {
    elasticsearch {
      hosts => ["192.168.0.30:9200"]
      index => "secure-%{+YYYY.MM.dd}"
    }
  }
}
```

## Logstash - Configuration

- Pipelines
- Input
- Filter
- Output
- Sending logs via Rsyslog

GROK Variables
```
USERNAME [a-zA-Z0-9._-]+
USER %{USERNAME}
INT (?:[+-]?(?:[0-9]+))
BASE10NUM (?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))
NUMBER (?:%{BASE10NUM})
BASE16NUM (?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))
BASE16FLOAT \b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-
9A-Fa-f]+)))\b
POSINT \b(?:[1-9][0-9]*)\b
NONNEGINT \b(?:[0-9]+)\b
WORD \b\w+\b
NOTSPACE \S+
SPACE \s*
DATA .*?
GREEDYDATA .*
QUOTEDSTRING (?>(?<!\\)(?>"(?>\\.|[^\\"]+)+"|""|(?>'(?>\\.|[^\\']+)+')|''|(?>`(?>\\.|[^\\`]+)+`)|``))
UUID [A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}
MAC (?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})
CISCOMAC (?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})
WINDOWSMAC (?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})
COMMONMAC (?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})
IPV6 ((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|
((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:)
{5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-
9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|
2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-
9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-
4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]
{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9AFa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-
9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]
{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?
IPV4 (?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]
{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-
9])
IP (?:%{IPV6}|%{IPV4})
HOSTNAME \b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]
{0,62}))*(\.?|\b)
HOST %{HOSTNAME}
IPORHOST (?:%{HOSTNAME}|%{IP})
HOSTPORT %{IPORHOST}:%{POSINT}
PATH (?:%{UNIXPATH}|%{WINPATH})
UNIXPATH (?>/(?>[\w_%!$@:.,-]+|\\.)*)+
TTY (?:/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+))
WINPATH (?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+
URIPROTO [A-Za-z]+(\+[A-Za-z+]+)?
URIHOST %{IPORHOST}(?::%{POSINT:port})?
URIPATH (?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+
#URIPARAM \?(?:[A-Za-z0-9]+(?:=(?:[^&]*))?(?:&(?:[A-Za-z0-9]+(?:=(?:[^&]*))?)?)*)?
URIPARAM \?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]]*
URIPATHPARAM %{URIPATH}(?:%{URIPARAM})?
URI %{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%
{URIPATHPARAM})?
MONTH \b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|
Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b
MONTHNUM (?:0?[1-9]|1[0-2])
MONTHNUM2 (?:0[1-9]|1[0-2])
MONTHDAY (?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])
DAY (?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|
Sun(?:day)?)
YEAR (?>\d\d){1,2}
HOUR (?:2[0123]|[01]?[0-9])
MINUTE (?:[0-5][0-9])
SECOND (?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)
TIME (?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])
DATE_US %{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}
DATE_EU %{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}
ISO8601_TIMEZONE (?:Z|[+-]%{HOUR}(?::?%{MINUTE}))
ISO8601_SECOND (?:%{SECOND}|60)
TIMESTAMP_ISO8601 %{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%
{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?
DATE %{DATE_US}|%{DATE_EU}
DATESTAMP %{DATE}[- ]%{TIME}
TZ (?:[PMCE][SD]T|UTC)
DATESTAMP_RFC822 %{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}
DATESTAMP_RFC2822 %{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %
{ISO8601_TIMEZONE}
DATESTAMP_OTHER %{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}
DATESTAMP_EVENTLOG %{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%
{MINUTE}%{SECOND}
SYSLOGTIMESTAMP %{MONTH} +%{MONTHDAY} %{TIME}
PROG (?:[\w._/%-]+)
SYSLOGPROG %{PROG:program}(?:\[%{POSINT:pid}\])?
SYSLOGHOST %{IPORHOST}
SYSLOGFACILITY <%{NONNEGINT:facility}.%{NONNEGINT:priority}>
HTTPDATE %{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}
SYSLOGBASE %{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%
{SYSLOGHOST:logsource} %{SYSLOGPROG}:
COMMONAPACHELOG %{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%
{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%
{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%
{NUMBER:bytes}|-)
COMBINEDAPACHELOG %{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}
LOGLEVEL ([Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|
INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?
(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)
```

## Logstash Pipelines

- Elasticsearch server
  - 192.168.0.30
- Logstash Server
  - 192.168.0.32
- Linux Server
  - 192.168.0.33

## Logstash Instance
  - Data Source ->
  - Logstash Instance
    - Input plugin
    - filter plugin
    - Output plugin
  - -> Data Destination

**Flow**
```
Linux Server --> Logstash Server -[documents]-> Elasticsearch Server
```

Configuring the jvm.options for logstash
```bash
vim /etc/logstash/jvm.options
[...]
## JVM configuration

# Xms represents the initial size of total heap space
# Xmx represents the maximum size of total heap space

-Xms256m
-Xmx256m
```

Let's create a iptables rule to filter the logs
```bash
iptables -I INPUT -p tcp --dport 22 -j LOG --log-prefix "Port 22 Access " --log-level warning
```

Take a look at the log
```bash
tail -n 10 /var/log/kern.log
tail -n 10 /var/log/kern.log
May  7 19:14:06 kube-node01 kernel: [ 7290.207849] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=52 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2047 RES=0x00 ACK URGP=0
May  7 19:14:06 kube-node01 kernel: [ 7290.364019] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=88 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2048 RES=0x00 ACK PSH URGP=0
May  7 19:14:06 kube-node01 kernel: [ 7290.370825] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=52 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2047 RES=0x00 ACK URGP=0
May  7 19:14:06 kube-node01 kernel: [ 7290.484983] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=88 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2048 RES=0x00 ACK PSH URGP=0
May  7 19:14:06 kube-node01 kernel: [ 7290.485522] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=52 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2047 RES=0x00 ACK URGP=0
May  7 19:14:06 kube-node01 kernel: [ 7290.593421] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=88 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2048 RES=0x00 ACK PSH URGP=0
May  7 19:14:06 kube-node01 kernel: [ 7290.594197] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=52 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2047 RES=0x00 ACK URGP=0
May  7 19:14:07 kube-node01 kernel: [ 7290.751488] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=88 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2048 RES=0x00 ACK PSH URGP=0
May  7 19:14:07 kube-node01 kernel: [ 7290.764976] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=52 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2047 RES=0x00 ACK URGP=0
May  7 19:14:07 kube-node01 kernel: [ 7291.600907] Port 22 Access IN=enp0s3 OUT= MAC=08:00:27:e3:4e:38:08:00:27:69:64:7c SRC=192.168.0.105 DST=192.168.0.32 LEN=88 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=63796 DPT=22 WINDOW=2048 RES=0x00 ACK PSH URGP=0
```

Creating the pipeline for the flow on the logstash server
```bash
vim /etc/logstash/conf.d/sysconf.conf
input {

  syslog {
    port => 10514
    type => "system-logs"
  }

  file {
    path => [ "/var/log/kern.log" ]
    type => "iptables-log"
  }

}


filter {
  if [type] == "iptables-log" {
    grok {
      match => { "message" =>  "%{SYSLOGTIMESTAMP:ipt_timestamp} %{SYSLOGHOST:srv_hostname} %{DATA:syslog_program}\: \[%{GREEDYDATA:ipt_id}\] %{GREEDYDATA:prefix} IN=%{GREEDYDATA:interface_in} OUT=%{GREEDYDATA:interface_out} MAC=%{GREEDYDATA:mac_adress} SRC=%{IP:source_ip} DST=%{IP:dest_ip} %{GREEDYDATA:text} DPT=%{INT:dest_port} %{GREEDYDATA:msg}" }
      add_field => [ "receive_at", "%{@timestamp}" ]
      add_field => [ "receive_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "ipt_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {

  if [type] == "iptables-log" {
    elasticsearch {
      hosts => [ "192.168.0.30:9200" ]
      index => "iptables-log-%{+YYYY.MM.dd}"
    }
  }

  if [type] == "system-logs" {
    elasticsearch {
      hosts => [ "192.168.0.30:9200" ]
      index => "system-logs-%{+YYYY.MM.dd}"
    }
  }

}
```

Let's create another
Creating the pipeline for the flow on the logstash server
```bash
vim /etc/logstash/conf.d/auth.conf
input {
  file {
    path => [ "/var/log/auth.log" ]
    type => "secure-log"
  }
}

filter {
  if [type] == "secure-log" {
    grok {
      match => { "message" => ["%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} for (invalid user )?%{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]} port %{NUMBER:[system][auth][ssh][port]} ssh2(: %{GREEDYDATA:[system][auth][ssh][signature]})?",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} user %{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: Did not receive identification string from %{IPORHOST:[system][auth][ssh][dropped_ip]}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: \s*%{DATA:[system][auth][user]} :( %{DATA:[system][auth][sudo][error]} ;)? TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{DATA:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} groupadd(?:\[%{POSINT:[system][auth][pid]}\])?: new group: name=%{DATA:system.auth.groupadd.name}, GID=%{NUMBER:system.auth.groupadd.gid}",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} useradd(?:\[%{POSINT:[system][auth][pid]}\])?: new user: name=%{DATA:[system][auth][user][add][name]}, UID=%{NUMBER:[system][auth][user][add][uid]}, GID=%{NUMBER:[system][auth][user][add][gid]}, home=%{DATA:[system][auth][user][add][home]}, shell=%{DATA:[system][auth][user][add][shell]}$",
               "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} %{DATA:[system][auth][program]}(?:\[%{POSINT:[system][auth][pid]}\])?: %{GREEDYMULTILINE:[system][auth][message]}"] }
      pattern_definitions => {
        "GREEDYMULTILINE"=> "(.|\n)*"
      }
    }
  }
}


output {
  if [type] == "secure-log" {
    elasticsearch {
      hosts => ["192.168.0.30:9200"]
      index => "secure-%{+YYYY.MM.dd}"
    }
  }
}
```


Now on the Linux server
```bash
vim /etc/rsyslog.d/50-default.conf
[...]
*.* @@192.168.0.32:10514
```

Now let's restart the rsyslog
```bash
systemctl restart rsyslog
```

No on the Logstash Server
```bash
systemctl restart logstash
```

Now double check the log file
```bash
tail -f /var/log/logstash/logstash-plain.log
```


On Kibana interface select
- Management
  - Index Patterns
    - create index pattern
    - index pattern:
      - system-logs-*
        - Next Step
      - Time Filter field name:
        - @timestamp
          - Create index pattern

On Kibana interface select
- Management
  - Index Patterns
    - create index pattern
    - index pattern:
      - iptables-log-*
        - Next Step
      - Time Filter field name:
        - @timestamp
          - Create index pattern


Deleting an index with curl
```bash
curl -XDELETE 'http://192.168.0.30:9200/iptables-log'
```

## Elastic Courses
- https://training.elastic.co/learn-from-home?baymax=rtp&elektra=home&storm=sub2&rogue=default&iesrc=ctr

## OpenShift Portal
- https://learn.openshift.com/

