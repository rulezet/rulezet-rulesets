import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_194_2_Tro_90 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_194_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_195_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_196_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_199_2.vir, Virus.Delself_Trojan.GenericKD.38632388.vir, Virus.Delself_Trojan.GenericKD.38632388_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbb267b95e6f1c3639bb267d347d05a8bcf99f5b835fe605b1e86a7e7b3f857b"
    hash2       = "f973c575963c0b734123c57589e95689e1dd347e01b4aef76cf9a021a34e2e95"
    hash3       = "a49d5ee298caf7ee053ed46a206f8d8aa1abf3acfe61719798c0cf338f6a3c4f"
    hash4       = "4511810343ffe65473d950c6638c0d4e9237e7bf84d843e2c3e856bcc9cd5443"
    hash5       = "b70b8824ee319ffd7bd1c6e5ac319a3cb45f36dbb7eb5ea4d9a7a8c7b11df773"
    hash6       = "647a1b3c87218ae8531de8f198ad56c5e39b91093353bbc58f69d8086d5bfc1e"
    hash7       = "67866b2cc2c65627481090fda91056657f994fbd21ecd4e9ad258235ddd2a3ae"

  strings:
    $s1  = "adaptive " fullword ascii
    $s2  = "not enough " fullword ascii
    $s3  = "lete dynamic" fullword ascii
    $s4  = " return code" fullword ascii
    $s5  = "ly %s Model" fullword ascii
    $s6  = "=trueLf!each " fullword ascii
    $s7  = "profile 'w" fullword ascii
    $s8  = "sleep 500" fullword ascii
    $s9  = "Thunderbird g" fullword ascii
    $s10 = "IDATs found" fullword ascii
    $s11 = "Potential overflow" fullword ascii
    $s12 = "hell Dl" fullword ascii
    $s13 = "  exit " fullword ascii
    $s14 = "P24T Over" fullword ascii
    $s15 = ") tree" fullword ascii
    $s16 = "heXa(I" fullword ascii
    $s17 = "c(PeGa" fullword ascii
    $s18 = " swap %" fullword ascii
    $s19 = "#tally" fullword ascii
    $s20 = "by ASCII" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "1e31f5c802376e4482c519ed7f18135d" and (8 of them)
    ) or (all of them)
}