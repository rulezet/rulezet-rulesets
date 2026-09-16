rule Virus_Hijack_Gen_Trojan_Keylogger_kmwaaOmk5ybj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.Keylogger.kmwaaOmk5ybj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2441cd5de63bc373cd20c72af190e26a3b3ea3efb519e54b0134f952215615d5"

  strings:
    $s1 = "Microsoft .NET Framework 2.3.1.0" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}