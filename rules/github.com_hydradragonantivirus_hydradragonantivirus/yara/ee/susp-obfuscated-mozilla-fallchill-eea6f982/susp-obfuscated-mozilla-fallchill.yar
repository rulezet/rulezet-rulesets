rule SUSP_Obfuscated_Mozilla_fallchill {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_fallchill = "Mlzrooa" nocase ascii wide

  condition:
    all of them
}