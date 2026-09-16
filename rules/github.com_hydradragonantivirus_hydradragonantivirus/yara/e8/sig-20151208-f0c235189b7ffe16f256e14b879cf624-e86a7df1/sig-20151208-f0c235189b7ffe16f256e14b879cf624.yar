rule sig_20151208_f0c235189b7ffe16f256e14b879cf624 {
  meta:
    description = "datamaliciousorder - file 20151208_f0c235189b7ffe16f256e14b879cf624.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d904876fb0ea64cd2ffd9f6b2ff4c0d6c9bab05742b42e419b6ce0116bff3c8f"

  strings:
    $s1  = "push(\"108\");g.push(\"34\");g.push(\"59\");g.push(\"13\");g.push(\"10\");g.push(\"118\");g.push(\"97\");g.push(\"114\");g.push(" ascii
    $s2  = "push(\"106\");g.push(\"101\");g.push(\"99\");g.push(\"116\");g.push(\"40\");g.push(\"34\");g.push(\"77\");g.push(\"83\");g.push(" ascii
    $s3  = "push(\"69\");s.push(\"57\");s.push(\"55\");s.push(\"54\");s.push(\"72\");s.push(\"70\");s.push(\"89\");s.push(\"42\");s.push(\"4" ascii
    $s4  = "function pPKnkHheQgMrXwkHsTMbwUyJYgtmbgNigVCfuAjcBlsgqMErrZPufU(YRuOKOZtwtgPR,VssHJixKPapTWt){ return txDHOdTMePoZS[ApiYl(YRuOKO" ascii
    $s5  = "push(\"121\");s.push(\"41\");s.push(\"59\");s.push(\"32\");s.push(\"105\");s.push(\"102\");s.push(\"32\");s.push(\"40\");s.push(" ascii
    $s6  = "var txDHOdTMePoZS=[];for(PVASUId=(-742+742)/859;PVASUId<(69296+336)/544;PVASUId++){txDHOdTMePoZS[PVASUId]=String.fromCharCode(PV" ascii
    $s7  = "function MaZhsfTvZBkQYlCyE(JgyFv){qlXjHUlIMVb= '';for(NfhgQAZvVSj=(-163+163)/227; NfhgQAZvVSj < (436+774)/605; NfhgQAZvVSj++) {V" ascii
    $s8  = ";}} return qlXjHUlIMVb}" fullword ascii
    $s9  = ";return rRocW;}function dFysbQTLnEhhKsE(NnuRbbBkriEWVvjes){eval(NnuRbbBkriEWVvjes)}" fullword ascii
    $s10 = "push(\"40\");g.push(\"49\");g.push(\"50\");g.push(\"54\");g.push(\"53\");g.push(\"56\");g.push(\"50\");g.push(\"44\");g.push(\"3" ascii
    $s11 = "ASUId)}function ApiYl(rlHKosNOIvP,FOXIdetoLDkSo,BLdGVgLe){rHmF=parseInt(rlHKosNOIvP,FOXIdetoLDkSo);rRocW=rHmF.toString(BLdGVgLe)" ascii
    $s12 = "push(\"46\");s.push(\"111\");s.push(\"112\");s.push(\"101\");s.push(\"110\");s.push(\"40\");s.push(\"41\");s.push(\"59\");s.push" ascii
    $s13 = "lxDLocIq[NfhgQAZvVSj]=(-331+331)/288; while(true) { if(VlxDLocIq[NfhgQAZvVSj] > JgyFv[NfhgQAZvVSj].length-(95+794)/889) { break;" ascii
    $s14 = "function MaZhsfTvZBkQYlCyE(JgyFv){qlXjHUlIMVb= '';for(NfhgQAZvVSj=(-163+163)/227; NfhgQAZvVSj < (436+774)/605; NfhgQAZvVSj++) {V" ascii
    $s15 = "function pPKnkHheQgMrXwkHsTMbwUyJYgtmbgNigVCfuAjcBlsgqMErrZPufU(YRuOKOZtwtgPR,VssHJixKPapTWt){ return txDHOdTMePoZS[ApiYl(YRuOKO" ascii
    $s16 = "push(\"116\");s.push(\"117\");s.push(\"115\");s.push(\"32\");s.push(\"61\");s.push(\"61\");s.push(\"32\");s.push(\"52\");s.push(" ascii
    $s17 = "function PLZpENGvndt(luRxMEMU,OofnFg){return luRxMEMU.split(OofnFg)}" fullword ascii
    $s18 = "function iZgekpM(EkCetwkAfwxzfUCIbXekDhdzaeLJKcArlaiD) {return !isNaN(parseFloat(EkCetwkAfwxzfUCIbXekDhdzaeLJKcArlaiD)) && isFin" ascii
    $s19 = "function iZgekpM(EkCetwkAfwxzfUCIbXekDhdzaeLJKcArlaiD) {return !isNaN(parseFloat(EkCetwkAfwxzfUCIbXekDhdzaeLJKcArlaiD)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}