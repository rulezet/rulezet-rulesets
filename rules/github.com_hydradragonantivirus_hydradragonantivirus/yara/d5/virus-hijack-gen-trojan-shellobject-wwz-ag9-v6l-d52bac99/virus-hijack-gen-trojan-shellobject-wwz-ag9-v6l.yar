rule Virus_Hijack_Gen_Trojan_ShellObject_wWZ_aG9_v6l {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wWZ@aG9@v6l.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ae3e9602a0c955983ef4d434ec4864e61e4162d0dfc7aac8e849a6dfb01e2be"

  strings:
    $s1 = "9H(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "9H(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}