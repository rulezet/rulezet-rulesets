rule Virus_Hijack_Trojan_GenericKDZ_103285_393 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_393.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69854970aa73e94e1bda15a1962369aa049a55ea79794d24a3b1042c4bd9caa2"

  strings:
    $s1 = "<{available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}