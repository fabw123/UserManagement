Write-Host "Deploying Nexus OSS"

docker-compose -f .\docker-compose-nexus-oss.yml --env-file .noss-env up -d

Write-Host "Ports running:"
Write-Host "8081: Web site"
Write-Host "8082: Docker hub proxy"
Write-Host "8083: Docker local registry"
Write-Host "8084: Microsoft registry proxy"