rule VirusShareWin32HLLWAutoruner547_19_1 {
  meta:
    description = "datamaliciousorder - file VirusShareWin32HLLWAutoruner547_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55c01c3e351dc7e3c3d567bba01150e42314c51328b0e164963abcdf549f975a"

  strings:
    $s1 = "Heco pememejajajizox xajokugeyalup xekos cigogunofedimu. Peludayehehiw zepivicitekob xowoge gusagofewid. Leyifobamoj wupaxaroca " ascii
    $s2 = "ce muwatop rixurapihoc. Xikab. Mode yodacitiyumuxe. Tev ropucopodivunu yuhezufop pap. Teviduxo pahosefoy ficiximaput ruxicipebe." ascii
    $s3 = "Mis tonic tazitodesaluso tohumawew zovoginipak" fullword ascii
    $s4 = "YPuzodobopi zisotumuboxo bipabunofixo tegalewikic pihalapaxeku sahasuwolok tate puwokigufe:Zovuv lizezedesebanew dukomehesex sif" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}