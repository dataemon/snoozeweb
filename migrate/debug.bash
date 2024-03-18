git pull
cd src/
docker build --rm --tag=nexus.privatehost.com:8444/orgname/snoozeweb/snooze_migrate:latest .
cd ..
docker-compose -f docker-compose.yaml run --rm snooze_migrate


