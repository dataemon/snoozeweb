# snoozeweb

snoozeweb deployment repo

```
# source code:
https://github.com/dataemon/snooze.git
https://github.com/dataemon/snooze_plugins.git
https://github.com/dataemon/snooze_client.git
```

## package docker images

```
cd /path-to-snoozeweb/docker/plugins/syslog
docker build --rm --tag=nexus.privatehost.com:8444/orgname/snoozeweb/syslog:latest .
cd /path-to-snoozeweb/docker/plugins/snmptrap
docker build --rm --tag=nexus.privatehost.com:8444/orgname/snoozeweb/snmptrap:latest .
cd /path-to-snoozeweb/migrate/src
docker build --rm --tag=nexus.privatehost.com:8444/orgname/snoozeweb/snooze_migrate:latest .

docker push nexus.privatehost.com:8444/orgname/snoozeweb/syslog:latest
docker push nexus.privatehost.com:8444/orgname/snoozeweb/snmptrap:latest

docker pull nexus.privatehost.com:8442/nginx
docker pull nexus.privatehost.com:8442/snoozeweb/snooze
docker pull nexus.privatehost.com:8442/mongo:6.0.11
docker pull nexus.privatehost.com:8442/orgname/snoozeweb/syslog:latest
docker pull nexus.privatehost.com:8442/orgname/snoozeweb/snmptrap:latest
```

## Highly available deployment with Docker Swarm

```bash
source .env `or` . .env
echo $HOST1
echo $HOST2
echo $HOST3
export HOST1
export HOST2
export HOST3
# https://learnubuntu.com/export-command/

docker stack deploy -c docker-compose.yaml snoozeweb

# Wait until MongoDB containers are up
replicate="rs.initiate(); sleep(1000); cfg = rs.conf(); cfg.members[0].host = \"mongo1:27017\"; rs.reconfig(cfg); rs.add({ host: \"mongo2:27017\", priority: 0.5 }); rs.add({ host: \"mongo3:27017\", priority: 0.5 }); rs.status();"

docker exec -it $(docker ps -qf label=com.docker.swarm.service.name=snoozeweb_mongo1) /bin/bash -c "echo '${replicate}' | mongosh"

docker service ls

docker stack rm snoozeweb

```

## Migrate the old snooze to snoozeweb

```bash
cd ./migrate
docker-compose -f docker-compose.yaml run --rm snooze_migrate
```
