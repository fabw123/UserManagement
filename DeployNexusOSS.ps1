Write-Host "Deploying Nexus OSS"

docker-compose -f .\docker-compose-nexus-oss.yml --env-file .noss-env up -d