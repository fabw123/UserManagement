Write-Host "Building and tagging Image"
docker build -t localhost:8083/user_management:latest .

Write-Host "Pushing image to registry"
docker push localhost:8083/user_management:latest

Write-Host "Deploying services"
docker-compose -f .\docker-compose.yml up -d