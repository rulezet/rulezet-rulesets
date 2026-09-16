rule RUSSIANPANDA_Mal_Nitrogen: FILE {
  meta:
    description = "Detects Nitrogen campaign"
    author      = "RussianPanda"
    id          = "9d591f87-47ec-54ea-b0ae-26a0542733a0"
    date        = "2024-02-04"
    modified    = "2024-02-04"
    reference   = "https://github.com/RussianPanda95/Yara-Rules"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Nitrogen/mal_nitrogen.yar#L1-L15"
    license_url = "N/A"
    logic_hash  = "642d5a16c7fb217a297bba683221de474eb028ac48ec8f52be897eaa056acb9b"
    score       = 75
    quality     = 79
    tags        = "FILE"

  strings:
    $s1 = { 63 7C 77 7B F2 6B 6F C5 }
    $s2 = { 52 09 6A D5 30 36 A5 38 }
    $s3 = "original_install"
    $s4 = "C:\\Users\\Public\\Download"
    $s5 = { 25 00 43 00 55 00 52 00 52 00 45 00 4E 00 54 00 5F 00 44 00 45 00 52 00 45 00 43 00 54 00 4F 00 52 00 59 00 25 }
    $s6 = "NitrogenTarget"

  condition:
    uint16(0) == 0x5A4D and 5 of them
}