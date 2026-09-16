rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aOU94xe_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ff87095654dd1e534fc81619b2cb4c5dbbd2f7ae4cf83ce5e9f859c7d3187f"

  strings:
    $s1 = "e;alEf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}