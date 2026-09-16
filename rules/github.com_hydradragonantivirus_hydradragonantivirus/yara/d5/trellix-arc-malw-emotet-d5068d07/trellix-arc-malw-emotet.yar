rule TRELLIX_ARC_MALW_Emotet: FINANCIAL FILE {
  meta:
    description    = "Rule to detect unpacked Emotet"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "5bc83065-dfdd-56b7-9983-200bff35c8b1"
    date           = "2020-07-21"
    modified       = "2020-08-14"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_emotet.yar#L1-L32"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "223e4453a6c3b56b0bc0f91147fa55ea59582d64b8a5c08f1f8d06026044065e"
    score          = 75
    quality        = 70
    tags           = "FINANCIAL, FILE"
    rule_version   = "v1"
    malware_type   = "financial"
    malware_family = "Backdoor:W32/Emotet"
    actor_type     = "Cybercrime"
    hash1          = "a6621c093047446e0e8ae104769af93a5a8ed147ab8865afaafbbd22adbd052d"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"

  strings:
    $pattern_0 = { 8b 45 fc 8b e5 5d c3 55 8b ec }
    $pattern_1 = { 3c 39 7e 13 3c 61 7c 04 3c 7a 7e 0b 3c 41 }
    $pattern_2 = { 7c 04 3c 39 7e 13 3c 61 7c 04 3c 7a 7e 0b }
    $pattern_3 = { 5f 8b c6 5e 5b 8b e5 }
    $pattern_4 = { 5f 66 89 06 5e 5b }
    $pattern_5 = { 3c 30 7c 04 3c 39 7e 13 3c 61 7c 04 }
    $pattern_6 = { 53 56 57 8b fa 8b f1 }
    $pattern_7 = { 3c 39 7e 13 3c 61 7c 04 3c 7a 7e 0b }
    $pattern_8 = { 55 8b ec 83 ec 14 53 }
    $pattern_9 = { 5e 8b e5 5d c3 55 8b ec }

  condition:
    7 of them and filesize < 180224
}