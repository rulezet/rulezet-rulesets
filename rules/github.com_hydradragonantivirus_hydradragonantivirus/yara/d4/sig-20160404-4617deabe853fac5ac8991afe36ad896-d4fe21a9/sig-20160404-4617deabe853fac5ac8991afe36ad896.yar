rule sig_20160404_4617deabe853fac5ac8991afe36ad896 {
  meta:
    description = "datamaliciousorder - file 20160404_4617deabe853fac5ac8991afe36ad896.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e392ee216c79d4a9e19fbfc89d4c830a074427b2d7be4638e7ed68e6b09385c"

  strings:
    $s1  = "return LQDjqQB[0] + LQDjqQB[2] + LQDjqQB[4] + \".F\" + LQDjqQB[7] + LQDjqQB[9] + LQDjqQB[12] + LQDjqQB[14];" fullword ascii
    $s2  = "var UG = true  , MdTW = ZTL[7] + ZTL[9] + ZTL[11];" fullword ascii
    $s3  = "var LQDjqQB = svISp(rbwMLhUBOM+\" \"+\"System uP moubH Obj rcMceA ect HbWvUQd tvFns\", \" \");" fullword ascii
    $s4  = "Eioq.open(EDIPS,hiNtK,false);" fullword ascii
    $s5  = "function VVYOBci(whXS) {" fullword ascii
    $s6  = "return ZZVkp;" fullword ascii
    $s7  = "function WaBi(jFATy,AFNmS) {" fullword ascii
    $s8  = "function utuS(QtBZv) {" fullword ascii
    $s9  = "function svISp(VKt,JPblC) {" fullword ascii
    $s10 = "EVK = C; break; " fullword ascii
    $s11 = "if (cMMmA == 730-530){return true;} else {return false;}" fullword ascii
    $s12 = "return jImI;" fullword ascii
    $s13 = "return fkQsMFD;" fullword ascii
    $s14 = "function nezb(zrZEr) {" fullword ascii
    $s15 = "function clBh(ODBYl) {" fullword ascii
    $s16 = "return new ActiveXObject(Fjha);" fullword ascii
    $s17 = "function uFUeo(gXqtglKP,bgio) {" fullword ascii
    $s18 = "function DBpZxADp(WoKq) {" fullword ascii
    $s19 = "function MPcGK(jqrkOn) {" fullword ascii
    $s20 = "if (ODBYl > 166776-465){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}