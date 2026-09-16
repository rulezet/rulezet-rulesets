rule sig_20151208_ec63916102398ff49c41e3cd088af3f8 {
  meta:
    description = "datamaliciousorder - file 20151208_ec63916102398ff49c41e3cd088af3f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69d9e3dbd3b7881039642054faf25175adb5b517ce5074ff4bdc41dc93d9ca6e"

  strings:
    $s1  = "push(\"108\");R.push(\"117\");R.push(\"100\");R.push(\"101\");R.push(\"115\");R.push(\"47\");R.push(\"112\");R.push(\"111\");R.p" ascii
    $s2  = "function mFnEowp(LZxhvVScqjbNwhjIZuHtthWNfjRvRFhVJDee) {return !isNaN(parseFloat(LZxhvVScqjbNwhjIZuHtthWNfjRvRFhVJDee)) && isFin" ascii
    $s3  = "function mFnEowp(LZxhvVScqjbNwhjIZuHtthWNfjRvRFhVJDee) {return !isNaN(parseFloat(LZxhvVScqjbNwhjIZuHtthWNfjRvRFhVJDee)) && isFin" ascii
    $s4  = ";return GEMtO;}function QbAVxVFPfDZUsxX(clcxWkQHtaNWyQxmj){eval(clcxWkQHtaNWyQxmj)}" fullword ascii
    $s5  = "function OFWuLBgIdxsKxfGUS(NDWpP){PysdgNobPDp= '';for(IODaFZRcLbS=(-993+993)/892; IODaFZRcLbS < (448+762)/605; IODaFZRcLbS++) {g" ascii
    $s6  = "push(\"49\");v.push(\"57\");v.push(\"45\");v.push(\"49\");v.push(\"57\");v.push(\"50\");v.push(\"41\");v.push(\"32\");v.push(\"3" ascii
    $s7  = "function vmfacNJHiBn(wTfhZqoB,CzVuTV){return wTfhZqoB.split(CzVuTV)}" fullword ascii
    $s8  = "LeSlQpzt[IODaFZRcLbS]=(-275+275)/627; while(true) { if(gLeSlQpzt[IODaFZRcLbS] > NDWpP[IODaFZRcLbS].length-(21+405)/426) { break;" ascii
    $s9  = "push(\"32\");v.push(\"55\");v.push(\"53\");v.push(\"53\");v.push(\"56\");v.push(\"49\");v.push(\"52\");v.push(\"59\");v.push(\"1" ascii
    $s10 = "push(\"108\");v.push(\"115\");v.push(\"101\");v.push(\"41\");v.push(\"59\");v.push(\"32\");v.push(\"108\");v.push(\"79\");v.push" ascii
    $s11 = "push(\"32\");v.push(\"118\");v.push(\"97\");v.push(\"114\");v.push(\"32\");v.push(\"77\");v.push(\"122\");v.push(\"32\");v.push(" ascii
    $s12 = "function OFWuLBgIdxsKxfGUS(NDWpP){PysdgNobPDp= '';for(IODaFZRcLbS=(-993+993)/892; IODaFZRcLbS < (448+762)/605; IODaFZRcLbS++) {g" ascii
    $s13 = "push(\"99\");v.push(\"47\");v.push(\"42\");v.push(\"111\");v.push(\"49\");v.push(\"104\");v.push(\"89\");v.push(\"49\");v.push(" ascii
    $s14 = "function reSijKyBoqkihieSLhdAoxLnsYzLJRyeNWibDfuaKIBEijpAchCfcI(gBXdNbgfaMjEQ,OTRYJIrvyoCzNN){ return jAgiUoeMvBfRH[xGrxx(gBXdNb" ascii
    $s15 = "push(\"34\");R.push(\"34\");R.push(\"41\");R.push(\"43\");R.push(\"34\");R.push(\"112\");R.push(\"116\");R.push(\"46\");R.push(" ascii
    $s16 = "function reSijKyBoqkihieSLhdAoxLnsYzLJRyeNWibDfuaKIBEijpAchCfcI(gBXdNbgfaMjEQ,OTRYJIrvyoCzNN){ return jAgiUoeMvBfRH[xGrxx(gBXdNb" ascii
    $s17 = "var jAgiUoeMvBfRH=[];for(SYnaRrY=(-715+715)/432;SYnaRrY<(67840+512)/534;SYnaRrY++){jAgiUoeMvBfRH[SYnaRrY]=String.fromCharCode(SY" ascii
    $s18 = "push(\"40\");v.push(\"40\");v.push(\"40\");v.push(\"110\");v.push(\"101\");v.push(\"119\");v.push(\"32\");v.push(\"68\");v.push(" ascii
    $s19 = "push(\"48\");v.push(\"59\");v.push(\"13\");v.push(\"10\");v.push(\"118\");v.push(\"97\");v.push(\"114\");v.push(\"32\");v.push(" ascii
    $s20 = "naRrY)}function xGrxx(WvfAeqbPkuQ,rkEIipkDDzwiK,iLkbeuUD){WciL=parseInt(WvfAeqbPkuQ,rkEIipkDDzwiK);GEMtO=WciL.toString(iLkbeuUD)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}