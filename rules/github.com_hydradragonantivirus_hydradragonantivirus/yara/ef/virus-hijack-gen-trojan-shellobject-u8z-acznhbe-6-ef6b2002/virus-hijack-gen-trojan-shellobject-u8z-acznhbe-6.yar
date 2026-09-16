rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d28590df648d03ef61cdd407d0ca4bfb2864156b1b3e4c24c4153cabc032124"

  strings:
    $s1 = "$available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}