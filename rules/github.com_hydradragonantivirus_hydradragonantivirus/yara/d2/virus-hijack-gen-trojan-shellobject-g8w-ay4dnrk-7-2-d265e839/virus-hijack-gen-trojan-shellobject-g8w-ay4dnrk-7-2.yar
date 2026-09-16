rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ffbd4dc462c3dd15150773d24838f9ec70245a50ae3747e80e3693fea0c947d"

  strings:
    $s1 = "Portions Copyright (c) 198" fullword ascii
    $s2 = "Sync!_iz3" fullword ascii
    $s3 = "L FROM:<" fullword ascii
    $s4 = "k/)From" fullword ascii
    $s5 = ">!Aqua" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}