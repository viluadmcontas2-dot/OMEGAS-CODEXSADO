param(
    [string]$CorpusRoot = "corpus/private"
)

$ErrorActionPreference = "Stop"

$sources = @(
    "C:\Users\hugov\Desktop\Landi Renzo\Landi Renzo Omegas\Resources.dll",
    "C:\Users\hugov\Desktop\Landi Renzo\Landi Renzo Omegas\ProgBase.exe",
    "C:\Users\hugov\Desktop\Landi Renzo\LANDIXP\Landi Renzo Omegas\Firmware\EVO_L_#00567.ple",
    "C:\Users\hugov\Desktop\Landi Renzo\LANDIXP\Landi Renzo Omegas\Firmware\EVO_#01160.ple",
    "G:\Meu Drive\ARQUIVOS OMEGAS\PortmonLOGNOVO (1).zip"
)

New-Item -ItemType Directory -Force -Path $CorpusRoot | Out-Null

foreach ($source in $sources) {
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing corpus source: $source"
    }
    Copy-Item -LiteralPath $source -Destination $CorpusRoot -Force
}

python scripts/make_local_manifest.py --output artifacts/local-corpus-manifest.json @sources
