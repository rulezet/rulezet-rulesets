rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "780568b047e65ff344ec5b8122b4048064d64027251a784f016a641c0fd8361f"

  strings:
    $s1 = "qavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}