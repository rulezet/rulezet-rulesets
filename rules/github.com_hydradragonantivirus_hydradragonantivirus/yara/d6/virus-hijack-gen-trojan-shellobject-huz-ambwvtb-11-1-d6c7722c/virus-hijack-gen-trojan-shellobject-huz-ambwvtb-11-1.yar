rule Virus_Hijack_Gen_Trojan_ShellObject_huZ_amBwvTb_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.huZ@amBwvTb_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e3fb4686fabbbac242491e810ca16d2fe5148aba2889efb2fe88af2ba7ab010"

  strings:
    $s1 = "!Error Down" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}