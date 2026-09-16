rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_116 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_116.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18a4e520d854512e06c38301df203b8c636064ccf68cc285057bb79fb77772ba"

  strings:
    $s1 = "Roxy;ZQ6`cqHdKMDO" fullword ascii
    $s2 = "S}o>IId2WqH%SWord" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}