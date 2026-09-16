rule sig_20151208_24679f8354a902d9594b6f1e0b71691a {
  meta:
    description = "datamaliciousorder - file 20151208_24679f8354a902d9594b6f1e0b71691a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8598c338f22c64d9757a37f86cad29df1270c0a262292cd01a1166b16642fa3a"

  strings:
    $s1  = "function XKygJnE(tUrxgmNPwHaxPibwCghycRGZlbhbtQBxFndo) {return !isNaN(parseFloat(tUrxgmNPwHaxPibwCghycRGZlbhbtQBxFndo)) && isFin" ascii
    $s2  = "function XKygJnE(tUrxgmNPwHaxPibwCghycRGZlbhbtQBxFndo) {return !isNaN(parseFloat(tUrxgmNPwHaxPibwCghycRGZlbhbtQBxFndo)) && isFin" ascii
    $s3  = "push(\"108\");m.push(\"117\");m.push(\"100\");m.push(\"101\");m.push(\"115\");m.push(\"47\");m.push(\"112\");m.push(\"111\");m.p" ascii
    $s4  = "push(\"45\");F.push(\"54\");F.push(\"50\");F.push(\"53\");F.push(\"41\");F.push(\"32\");F.push(\"32\");F.push(\"123\");F.push(\"" ascii
    $s5  = "push(\"77\");m.push(\"76\");m.push(\"72\");m.push(\"34\");m.push(\"59\");m.push(\"13\");m.push(\"10\");m.push(\"118\");m.push(\"" ascii
    $s6  = "push(\"95\");m.push(\"112\");m.push(\"97\");m.push(\"103\");m.push(\"101\");m.push(\"115\");m.push(\"95\");m.push(\"115\");m.pus" ascii
    $s7  = "Df)}function rAQIA(RKnCWUEwjxH,nWvADptovTXja,DpOCyYQd){HCfC=parseInt(RKnCWUEwjxH,nWvADptovTXja);xoiuk=HCfC.toString(DpOCyYQd);re" ascii
    $s8  = "push(\"61\");F.push(\"32\");F.push(\"103\");F.push(\"59\");F.push(\"32\");F.push(\"98\");F.push(\"114\");F.push(\"101\");F.push(" ascii
    $s9  = "push(\"32\");F.push(\"103\");F.push(\"61\");F.push(\"66\");F.push(\"74\");F.push(\"69\");F.push(\"59\");F.push(\"32\");F.push(\"" ascii
    $s10 = "turn xoiuk;}function evANGcBqPUhDgDW(BcDPwVvGzHFaTYvmU){eval(BcDPwVvGzHFaTYvmU)}" fullword ascii
    $s11 = "function aRDtOnpPYnuFQszDK(BXUYU){BgSGLyTIIOn= '';for(sloShZrpmIy=(-475+475)/354; sloShZrpmIy < (176+278)/227; sloShZrpmIy++) {P" ascii
    $s12 = "wpSVrIcv[sloShZrpmIy]=(-226+226)/102; while(true) { if(PwpSVrIcv[sloShZrpmIy] > BXUYU[sloShZrpmIy].length-(62+569)/631) { break;" ascii
    $s13 = "function aRDtOnpPYnuFQszDK(BXUYU){BgSGLyTIIOn= '';for(sloShZrpmIy=(-475+475)/354; sloShZrpmIy < (176+278)/227; sloShZrpmIy++) {P" ascii
    $s14 = "push(\"121\");F.push(\"32\");F.push(\"32\");F.push(\"123\");F.push(\"13\");F.push(\"10\");F.push(\"9\");F.push(\"112\");F.push(" ascii
    $s15 = "push(\"79\");m.push(\"98\");m.push(\"106\");m.push(\"101\");m.push(\"99\");m.push(\"116\");m.push(\"40\");m.push(\"34\");m.push(" ascii
    $s16 = "push(\"32\");F.push(\"103\");F.push(\"43\");F.push(\"43\");F.push(\"41\");F.push(\"32\");F.push(\"32\");F.push(\"123\");F.push(" ascii
    $s17 = "push(\"59\");F.push(\"13\");F.push(\"10\");F.push(\"118\");F.push(\"97\");F.push(\"114\");F.push(\"32\");F.push(\"100\");F.push(" ascii
    $s18 = "}} return BgSGLyTIIOn}" fullword ascii
    $s19 = "function jjOubHGCSfX(sLrvBZXt,BeZIKd){return sLrvBZXt.split(BeZIKd)}" fullword ascii
    $s20 = "push(\"100\");F.push(\"75\");F.push(\"119\");F.push(\"46\");F.push(\"112\");F.push(\"111\");F.push(\"115\");F.push(\"105\");F.pu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}