rule Trojan_Autorun_Trojan_GenericKD_72517131_152_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_152_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cb66a8e24d5a7279432087158eda4d10cd94669d5b8e104d35621bf018f7fef"

  strings:
    $s1 = "1 Year Subscription: A program " fullword ascii
    $s2 = "1to circumvent technical protection measures in the software, reverse engineer, decompile, or disassemble" fullword ascii
    $s3 = "jlP. Force Majeure" fullword ascii
    $s4 = "Does Microsoft provide a LIMITED WA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}