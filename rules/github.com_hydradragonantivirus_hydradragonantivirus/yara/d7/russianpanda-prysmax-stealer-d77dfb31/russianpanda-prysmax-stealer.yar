rule RUSSIANPANDA_Prysmax_Stealer: FILE {
  meta:
    description = "Detects Prysmax Stealer"
    author      = "RussianPanda"
    id          = "97ab92b8-1771-5881-9cd1-d8ff76b8f380"
    date        = "2024-01-09"
    modified    = "2024-01-10"
    reference   = "https://www.cyfirma.com/outofband/new-maas-prysmax-launches-fully-undetectable-infostealer/"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Prysmax Stealer/prysmax_stealer.yar#L1-L21"
    license_url = "N/A"
    logic_hash  = "869eee7dd5209bdea98c248791b9ac911e3daabe6d440aa62aecefa43539a41c"
    score       = 75
    quality     = 73
    tags        = "FILE"

  strings:
    $a1 = "######################"
    $s2 = "sprysmax"
    $s3 = "VCRUNTIME140.dll"
    $s4 = "VCRUNTIME140_1.dll"
    $s5 = "MSVCP140.dll"
    $s6 = "PyInstaller"

  condition:
    all of ($s*) and uint16(0) == 0x5A4D and $a1 in (9600000..filesize) and #a1 > 600 and filesize > 60MB and filesize < 200MB
}