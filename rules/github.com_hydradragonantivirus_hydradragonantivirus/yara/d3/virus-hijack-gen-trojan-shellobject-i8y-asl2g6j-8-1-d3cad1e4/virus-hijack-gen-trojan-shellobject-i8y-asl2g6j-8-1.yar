rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47075f43ae57e74e2c85e4504cd25df4ad290f22da7b7dfd110dcac8f10bf38d"

  strings:
    $s1 = "Heco pememejajajizox xajokugeyalup xekos cigogunofedimu. Peludayehehiw zepivicitekob xowoge gusagofewid. Leyifobamoj wupaxaroca " ascii
    $s2 = "ce muwatop rixurapihoc. Xikab. Mode yodacitiyumuxe. Tev ropucopodivunu yuhezufop pap. Teviduxo pahosefoy ficiximaput ruxicipebe." ascii
    $s3 = "Mis tonic tazitodesaluso tohumawew zovoginipak" fullword ascii
    $s4 = "YPuzodobopi zisotumuboxo bipabunofixo tegalewikic pihalapaxeku sahasuwolok tate puwokigufe:Zovuv lizezedesebanew dukomehesex sif" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}