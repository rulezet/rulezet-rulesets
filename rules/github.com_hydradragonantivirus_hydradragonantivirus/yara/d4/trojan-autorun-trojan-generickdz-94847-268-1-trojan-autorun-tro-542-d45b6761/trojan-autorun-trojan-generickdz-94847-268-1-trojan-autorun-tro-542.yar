import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_94847_268_1_Trojan_Autorun_Tro_542 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.94847_268_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_367_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_20_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_239_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqIm5Rf.vir, Virus.Hijack_Trojan.Agent.DQQO_22.vir, Virus.Hijack_Trojan.Agent.DQQO_285.vir, Virus.Hijack_Trojan.Agent.DQQO_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bf20e1c8c367bfe848c3416afe2c43ca7648244396a5fb0af88f5805fbed181"
    hash2       = "277175bead764d90dff6c981d547f03e6bd5c35f64689259d7ffd9813db66e6e"
    hash3       = "e287104c098d25d0e922c493d6eaf764f4c1d4abe219a822eab854903d3a75fd"
    hash4       = "ec1fb22450e7a0abcc05ba2ae9a4fa3aeae2561b0a52fae66026520bff19314c"
    hash5       = "28f66e32d7c3ce461a2089c8132ffeb6f814911a1a1cf4fbbb249ed6dd9acf94"
    hash6       = "bdd026cc8f7a01ea35a2e233da9bd047143c06246efa22bffc559e936f450705"
    hash7       = "cdd29902e0074f1f65edb16daacd17b26f08009b0996def8b37c1849da4e598e"
    hash8       = "fa103d8c14354aa96f1c01f5810f70a0903470ac662e3b3c39ca35f590da9eb4"

  strings:
    $s1 = " go.microsoft.com/fwlink/?LinkId=261245 (Arbitration Procedure)o" fullword ascii
    $s2 = "\\?S8Q0reduced by applying the discount specified above. Notwithstanding anything to the contrary in the previous three sentence" ascii
    $s3 = "\\?S8Q0reduced by applying the discount specified above. Notwithstanding anything to the contrary in the previous three sentence" ascii
    $s4 = ") and ordered OracleC" fullword ascii
    $s5 = "assets, owned or managed for others, which were previously leased and active on the program, including assets from termF" fullword ascii
    $s6 = "is program cannot be run in DOS mode." fullword ascii
    $s7 = "Technical Reference Manuals5." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "7ddf1025357687e2d1a58fbb522333a8" and (all of them)
    ) or (all of them)
}