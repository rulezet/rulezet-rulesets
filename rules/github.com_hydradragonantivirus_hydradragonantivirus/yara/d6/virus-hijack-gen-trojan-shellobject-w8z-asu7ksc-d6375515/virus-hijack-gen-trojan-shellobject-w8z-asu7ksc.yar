rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aSU7kSc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aSU7kSc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5335974ea5575acfbd6a8f1041aff0241efb096972fa615b4991000461a5d3a"

  strings:
    $s1 = "pLUP<_N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}