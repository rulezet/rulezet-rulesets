rule sig_20160526_83a242fa68e63c423363836b2cb61ac6 {
  meta:
    description = "datamaliciousorder - file 20160526_83a242fa68e63c423363836b2cb61ac6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f111617ffc4a858d7bdd36faea43ac3f33c43e851e1c9ec7a995bed4ffaa70ec"

  strings:
    $s1  = "function ioAPh(repMafcxAWrTW) {var YoKFich = SVHHaYoQQvdJwHA.join(NVeHhn[0]);var QFKqVkLwoe, MjCSedxAJmbVYsR, YGarjZcWYqMvZzqeQ," ascii
    $s2  = "h.pow(Math.cos(266), 2) - 1))-914)) OWItvulzFE += m(QFKqVkLwoe);else if (PhTwycrizBFO == (862 + Math.round((Math.pow(Math.sin(72" ascii
    $s3  = "4), 2) + Math.pow(Math.cos(724), 2) - 1))-798)) OWItvulzFE += eSOYNHQYpTzBwG(QFKqVkLwoe, MjCSedxAJmbVYsR);else OWItvulzFE += PUw" ascii
    $s4  = "function paZvOSYirsyIsMzWwZIvymrO(PteMPTaNCazoFOG,omQDnIAOLH){return PteMPTaNCazoFOG.charAt(omQDnIAOLH);}" fullword ascii
    $s5  = "function AUXugdJGqlIiLclogDKst(fSVcuiQ,kxBUHUHRlGfOhYCgFYmjciV){return fSVcuiQ.indexOf(kxBUHUHRlGfOhYCgFYmjciV);}" fullword ascii
    $s6  = "function eSOYNHQYpTzBwG(gZkhZGZkcUpBdGhAVA,mFMBDomIWxnQLbLcqnXVEJky){return String.fromCharCode(gZkhZGZkcUpBdGhAVA,mFMBDomIWxnQL" ascii
    $s7  = "function eSOYNHQYpTzBwG(gZkhZGZkcUpBdGhAVA,mFMBDomIWxnQLbLcqnXVEJky){return String.fromCharCode(gZkhZGZkcUpBdGhAVA,mFMBDomIWxnQL" ascii
    $s8  = "function ioAPh(repMafcxAWrTW) {var YoKFich = SVHHaYoQQvdJwHA.join(NVeHhn[0]);var QFKqVkLwoe, MjCSedxAJmbVYsR, YGarjZcWYqMvZzqeQ," ascii
    $s9  = "function m(GzKYzuJUGLs){return String.fromCharCode(GzKYzuJUGLs);}" fullword ascii
    $s10 = "function PUwTHCokPtchHU(YJpGmKwWhHiZtnKME,yfethx,wGCubgKlFdTleBgHoumK){return String.fromCharCode(YJpGmKwWhHiZtnKME,yfethx,wGCub" ascii
    $s11 = "function PUwTHCokPtchHU(YJpGmKwWhHiZtnKME,yfethx,wGCubgKlFdTleBgHoumK){return String.fromCharCode(YJpGmKwWhHiZtnKME,yfethx,wGCub" ascii
    $s12 = "THCokPtchHU(QFKqVkLwoe, MjCSedxAJmbVYsR, YGarjZcWYqMvZzqeQ);} while (GWDAIcGiwrjZOMBdlAuq < repMafcxAWrTW.length);return OWItvul" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}