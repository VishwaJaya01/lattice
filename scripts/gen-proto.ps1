Param()

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$protoDir = Join-Path $root "proto"
$goOut = Join-Path $protoDir "latticev1"
$rustOut = Join-Path $protoDir "gen\rust"
$goFbOut = Join-Path $protoDir "gen\go"

foreach ($tool in @("protoc", "protoc-gen-go", "protoc-gen-go-grpc", "flatc")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool '$tool' not found on PATH."
    }
}

New-Item -ItemType Directory -Force -Path $goOut | Out-Null
New-Item -ItemType Directory -Force -Path $rustOut | Out-Null
New-Item -ItemType Directory -Force -Path $goFbOut | Out-Null

& protoc -I $protoDir `
  --go_out "paths=source_relative:$goOut" `
  --go-grpc_out "paths=source_relative:$goOut" `
  (Join-Path $protoDir "lattice.proto")

& flatc --rust --scoped-enums -o $rustOut (Join-Path $protoDir "lattice.fbs")
& flatc --go --scoped-enums -o $goFbOut (Join-Path $protoDir "lattice.fbs")

Write-Host "Generated Go protobufs in $goOut"
Write-Host "Generated Rust FlatBuffers in $rustOut"
Write-Host "Generated Go FlatBuffers in $goFbOut"
