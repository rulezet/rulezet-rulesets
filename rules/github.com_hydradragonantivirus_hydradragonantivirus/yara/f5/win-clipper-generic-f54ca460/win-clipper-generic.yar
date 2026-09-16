rule win_clipper_generic {
  meta:
    id             = "a94b3d01-dbc7-41e4-8d45-793bf443b1d2"
    version        = "1.0"
    description    = "Clipper found during investigation: 892a9edb03db3fd88fecc1e1a2f56a7339f16f6734e8d77e6538ea2c8c9026d6"
    author         = "Sekoia.io"
    creation_date  = "2024-07-03"
    classification = "TLP:CLEAR"

  strings:
        $s = "$ranpth = if ((Get-Random) % 2) { Join-Path $env:TEMP \"$ran.ps1\" } else { Join-Path $env:APPDATA \"$ran.ps1\" }"

  condition:
    filesize > 1KB and
    all of them
}