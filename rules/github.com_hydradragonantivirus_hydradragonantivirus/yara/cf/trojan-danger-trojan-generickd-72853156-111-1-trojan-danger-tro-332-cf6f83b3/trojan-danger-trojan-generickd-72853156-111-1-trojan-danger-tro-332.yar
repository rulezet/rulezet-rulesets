import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_111_1_Trojan_Danger_Tro_332 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_111_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_114_1.vir, Virus.Autorun_Gen.Variant.Ransom.Higuniel.4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d86a169b6beba58b8bf14c6d69c611c512a59ef3a4f711edb37144d3becd685"
    hash2       = "3cce5988ed62b84eedd77842ee41b51bd152b5936737353c54bd82f9f888725f"
    hash3       = "86f40794653bc347e93e097f721f1c2aa80bac8ca983f4a7f77c22a49b7b7e62"

  strings:
    $s1  = "ttempt to load the C {" fullword ascii
    $s2  = "~Alloc;runtime error " fullword ascii
    $s3  = "library i" fullword ascii
    $s4  = "?3=%s&type" fullword ascii
    $s5  = ". It *most likex" fullword ascii
    $s6  = "Create Child C" fullword ascii
    $s7  = "known>wBE" fullword ascii
    $s8  = "Please co" fullword ascii
    $s9  = "2not enough space." fullword ascii
    $s10 = "! heap%{27'0<" fullword ascii
    $s11 = "result of calll" fullword ascii
    $s12 = "An application has made a" fullword ascii
    $s13 = "is assembly during nJv" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "4d12409423f75786a52033f8c6a5a133" and (8 of them)
    ) or (all of them)
}