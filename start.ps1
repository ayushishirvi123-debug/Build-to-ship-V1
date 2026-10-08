$nodeDir = Resolve-Path "$PSScriptRoot\node-v20.18.0-win-x64"
$env:Path = "$($nodeDir.Path);" + $env:Path

Write-Host "Starting Backend..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit -Command `" `$env:Path = '$($nodeDir.Path);' + `$env:Path; cd backend; npm run dev:backend `""

Write-Host "Starting Frontend..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit -Command `" `$env:Path = '$($nodeDir.Path);' + `$env:Path; cd frontend; npm run dev:frontend `""
