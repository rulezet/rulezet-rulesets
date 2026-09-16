rule Trojan_Autorun_Trojan_GenericKD_72517131_116_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_116_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea6b0ac9a91c0859b10015b5d43325266176025d01d2b32a7c29d0d59758993f"

  strings:
    $s1 = "IUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}