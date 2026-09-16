rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_72 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_72.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687c56f921a715c0116d05d6692526dd2c399f4d4f77bf455bbad30e7ec0f20"

  strings:
    $s1 = "j4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}