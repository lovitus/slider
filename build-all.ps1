# Cross-compile slider for multiple platforms
$ErrorActionPreference = "Continue"
$version = "0.1.2"
$outDir = "dist"
$binName = "slider"
$ldflags = "-s -w -X main.version=$version"

if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

$targets = @(
    @{ GOOS = "linux"; GOARCH = "386" },
    @{ GOOS = "linux"; GOARCH = "amd64" },
    @{ GOOS = "linux"; GOARCH = "arm64" },
    @{ GOOS = "linux"; GOARCH = "arm"; GOARM = "6" },
    @{ GOOS = "linux"; GOARCH = "arm"; GOARM = "7" },
    @{ GOOS = "linux"; GOARCH = "mips"; GOMIPS = "softfloat" },
    @{ GOOS = "linux"; GOARCH = "mipsle"; GOMIPS = "softfloat" },
    @{ GOOS = "linux"; GOARCH = "mips64" },
    @{ GOOS = "linux"; GOARCH = "mips64le" },
    @{ GOOS = "linux"; GOARCH = "riscv64" },
    @{ GOOS = "darwin"; GOARCH = "amd64" },
    @{ GOOS = "darwin"; GOARCH = "arm64" },
    @{ GOOS = "freebsd"; GOARCH = "386" },
    @{ GOOS = "freebsd"; GOARCH = "amd64" },
    @{ GOOS = "windows"; GOARCH = "386" },
    @{ GOOS = "windows"; GOARCH = "amd64" },
    @{ GOOS = "windows"; GOARCH = "arm64" }
)

$success = 0
$failed = @()
$total = $targets.Count

foreach ($t in $targets) {
    $suffix = "$($t.GOOS)-$($t.GOARCH)"
    if ($t.GOARM) { $suffix += "v$($t.GOARM)" }
    if ($t.GOMIPS -eq "softfloat") { $suffix += "-sf" }

    $ext = ""
    if ($t.GOOS -eq "windows") { $ext = ".exe" }

    $outName = "$binName-$suffix$ext"
    $outPath = Join-Path $outDir $outName
    $idx = [array]::IndexOf($targets, $t) + 1

    Write-Host "[$idx/$total] $suffix " -NoNewline -ForegroundColor Cyan

    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $env:CGO_ENABLED = "0"
    if ($t.GOARM) { $env:GOARM = $t.GOARM }  else { Remove-Item Env:\GOARM  -ErrorAction SilentlyContinue }
    if ($t.GOMIPS) { $env:GOMIPS = $t.GOMIPS } else { Remove-Item Env:\GOMIPS -ErrorAction SilentlyContinue }

    go build -ldflags $ldflags -trimpath -o $outPath .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED" -ForegroundColor Red
        $failed += $suffix
        continue
    }

    # Compress: gz for unix, zip for windows
    $binSize = (Get-Item $outPath).Length
    if ($t.GOOS -eq "windows") {
        $pkgName = Join-Path $outDir "$binName-$suffix-$version.zip"
        Compress-Archive -Path $outPath -DestinationPath $pkgName -Force
        $pkgSize = (Get-Item $pkgName).Length
    }
    else {
        $pkgName = Join-Path $outDir "$binName-$suffix-$version.gz"
        $raw = [System.IO.File]::ReadAllBytes($outPath)
        $ms = New-Object System.IO.MemoryStream
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionLevel]::Optimal)
        $gz.Write($raw, 0, $raw.Length)
        $gz.Close()
        [System.IO.File]::WriteAllBytes($pkgName, $ms.ToArray())
        $ms.Close()
        $pkgSize = (Get-Item $pkgName).Length
    }

    # Remove raw binary, keep only package
    Remove-Item $outPath -Force

    $binMB = [math]::Round($binSize / 1MB, 1)
    $pkgMB = [math]::Round($pkgSize / 1MB, 1)
    Write-Host "OK bin=${binMB}MB pkg=${pkgMB}MB" -ForegroundColor Green
    $success++
}

# Reset env
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
Remove-Item Env:\GOMIPS -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Build Summary ===" -ForegroundColor Yellow
Write-Host "Success: $success / $total"
if ($failed.Count -gt 0) {
    Write-Host "Failed: $($failed -join ', ')" -ForegroundColor Red
}
Write-Host "Packages: $outDir\"
