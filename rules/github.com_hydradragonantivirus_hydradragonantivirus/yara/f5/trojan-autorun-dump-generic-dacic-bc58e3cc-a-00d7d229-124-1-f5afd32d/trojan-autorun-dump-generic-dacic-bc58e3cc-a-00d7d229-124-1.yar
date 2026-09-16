rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_124_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_124_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01a8da97321dab0929a6807c22e73e9894c8265cb90e6168ed6426f0426ce1eb"

  strings:
    $s1 = "flOfwe]{qfOsuh[b~d`DPFzHD]UpKGmHUZUdW[{BL]_BPZ`HLuL_REfUG[UePF~TGglPr[fDGZz'eEfECE\\TG[FADE`IG)ZHD]~FPLUjKJ{HQFoS~~`IFF~T~j|UPLg" ascii
    $s2 = "flOfwe]{qfOsuh[b~d`DPFzHD]UpKGmHUZUdW[{BL]_BPZ`HLuL_REfUG[UePF~TGglPr[fDGZz'eEfECE\\TG[FADE`IG)ZHD]~FPLUjKJ{HQFoS~~`IFF~T~j|UPLg" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}