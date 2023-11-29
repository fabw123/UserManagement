Write-Host "Login into Docker Hub"
docker login --username admin --password Password1234 localhost:8083

Write-Host "Building and tagging Image"
docker build -t localhost:8083/user_management:latest Dockerfile

Write-Host "Pushing image to registry"
docker push localhost:8083/user_management:latest