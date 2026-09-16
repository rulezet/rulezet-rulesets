rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_amCvSwc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@amCvSwc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edeef3755b247a17a1d08c7a39ea327d4dfb4241265050f08fdfc5cd1376b06e"

  strings:
    $s1 = "QXUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}