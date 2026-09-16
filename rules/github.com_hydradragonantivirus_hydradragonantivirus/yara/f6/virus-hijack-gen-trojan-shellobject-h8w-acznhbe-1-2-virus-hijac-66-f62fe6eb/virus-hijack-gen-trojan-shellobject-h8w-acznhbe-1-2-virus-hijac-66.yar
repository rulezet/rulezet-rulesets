import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_1_2_Virus_Hijac_66 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb6504dce35506f80863be6da7874cff81a8c5544322f1e8cd4e050132fc641d"
    hash2       = "cffbafc868dadaa45420c56b5aa9a98fd0867cd2712ea4d03d71bf4f4eba74f6"

  strings:
    $s1 = "header parse error: [rc=%d, name='%s', value='%s']" fullword ascii
    $s2 = "The device contains hybrid MBR -- writing GPT only. You have to sync the MBR manually." fullword ascii
    $s3 = "The kernel still uses the old table. The new table will be used at the next reboot or after you run partprobe(8) or kpartx(8)." fullword ascii
    $s4 = "%zu primary, %d extended, %zu free" fullword ascii
    $s5 = "found a %s MBR" fullword ascii
    $s6 = "DOS: last possible sector for #%zu is %ju" fullword ascii
    $s7 = "DOS: unused sector for #%zu is %ju" fullword ascii
    $s8 = "Rufus alignment" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b10d16eedb1085ef7262dfc4ab03be6f" and (all of them)
    ) or (all of them)
}