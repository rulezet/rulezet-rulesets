rule TRELLIX_ARC_APT_Acidbox_Main_Module_Dll: BACKDOOR FILE {
  meta:
    description    = "Rule to detect the Main mode component of AcidBox"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "8c9beb0f-62f7-5788-8340-0b1ecdf54253"
    date           = "2020-07-24"
    modified       = "2020-08-14"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_acidbox.yar#L34-L65"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "db98e204742b8629074d47df301ffcbb2dfb977a4da91557fb50838aae79e777"
    score          = 75
    quality        = 70
    tags           = "BACKDOOR, FILE"
    rule_version   = "v1"
    malware_type   = "backdoor"
    malware_family = "Backdoor:W32/Acidbox"
    actor_type     = "APT"
    actor_group    = "Turla"
    hash1          = "eb30a1822bd6f503f8151cb04bfd315a62fa67dbfe1f573e6fcfd74636ecedd5"

  strings:
    $pattern_0 = { 77 07 b8 02 2d 03 a0 eb 05 e8 ?? ?? ?? ?? }
    $pattern_1 = { 44 03 c8 8b c3 41 d1 c6 33 c6 81 c6 d6 c1 62 ca c1 cb 02 33 c7 }
    $pattern_2 = { e9 ?? ?? ?? ?? 41 2b 5c 24 18 8b 45 dc 41 2b 44 24 08 41 01 5c 24 1c 41 01 44 24 0c 01 5f 1c }
    $pattern_3 = { 48 89 5c 24 08 57 48 83 ec 30 48 8b fa 33 db 48 85 c9 74 79 }
    $pattern_4 = { 48 89 5c 24 08 57 48 83 ec 30 49 8b d8 48 8b fa 48 83 64 24 58 00 85 c9 }
    $pattern_5 = { 48 89 87 e0 01 00 00 e9 ?? ?? ?? ?? 81 cb 00 10 03 a0 e9 ?? ?? ?? ?? 48 8b 87 a0 01 00 00 44 84 78 06 74 2e }
    $pattern_6 = { 4d 8b cc 4c 8d 05 96 c5 01 00 49 8b d4 48 8b ce e8 ?? ?? ?? ?? 49 8b 9d e0 01 00 00 c7 46 05 aa 99 33 55 }
    $pattern_7 = { 45 33 c0 8d 56 08 e8 ?? ?? ?? ?? 48 8b f0 48 89 44 24 60 48 85 c0 75 0b }
    $pattern_8 = { 48 8d 55 58 41 c1 ee 08 41 b8 02 00 00 00 44 88 75 59 e8 ?? ?? ?? ?? 4c 8b 4d e0 89 47 18 }
    $pattern_9 = { 4d 03 c2 4d 3b c2 4d 13 cc 4d 03 03 4d 3b 03 4d 89 03 4c 8b 13 }

  condition:
    7 of them and filesize < 550912
}