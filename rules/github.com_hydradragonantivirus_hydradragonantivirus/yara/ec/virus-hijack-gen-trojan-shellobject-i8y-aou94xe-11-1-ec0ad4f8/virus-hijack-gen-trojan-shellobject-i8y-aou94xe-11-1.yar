rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aOU94xe_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a10dea1a440b70d5f62ce3cc1f2dbe665c9e2a8b6293a692946e62b522829124"

  strings:
    $s1 = "Heco pememejajajizox xajokugeyalup xekos cigogunofedimu. Peludayehehiw zepivicitekob xowoge gusagofewid. Leyifobamoj wupaxaroca " ascii
    $s2 = "ce muwatop rixurapihoc. Xikab. Mode yodacitiyumuxe. Tev ropucopodivunu yuhezufop pap. Teviduxo pahosefoy ficiximaput ruxicipebe." ascii
    $s3 = "Mis tonic tazitodesaluso tohumawew zovoginipak" fullword ascii
    $s4 = "YPuzodobopi zisotumuboxo bipabunofixo tegalewikic pihalapaxeku sahasuwolok tate puwokigufe:Zovuv lizezedesebanew dukomehesex sif" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}