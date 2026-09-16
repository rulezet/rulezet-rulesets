rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "427a33f3df35a3fd1080b7b592e858e008820688d9c36e3532861585816220c7"

  strings:
    $s1 = "NuDGE)" fullword ascii
    $s2 = "W;keEN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}