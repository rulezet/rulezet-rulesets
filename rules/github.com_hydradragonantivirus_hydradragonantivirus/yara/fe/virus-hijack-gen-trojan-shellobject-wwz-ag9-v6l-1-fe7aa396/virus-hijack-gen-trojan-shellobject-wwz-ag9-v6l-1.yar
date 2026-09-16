rule Virus_Hijack_Gen_Trojan_ShellObject_wWZ_aG9_v6l_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wWZ@aG9@v6l_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05925a19be8b71cf104dd90cefd9e28b7cf70c29180dc8b23c8028c7962e3501"

  strings:
    $s1 = "e(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "e(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s3 = "and software vendors, so that they can use the information to i`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}