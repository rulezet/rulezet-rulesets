rule sig_20160525_7b6bba311837de5c32f182facb9b25d8 {
  meta:
    description = "datamaliciousorder - file 20160525_7b6bba311837de5c32f182facb9b25d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "311eaf6b123dc1b180170f0972613e30c0e372ef216d3d4b698f47a8280e9ad5"

  strings:
    $s1  = "function dCFJA(UrVCYQgXsUdKY) {var vjEoeEqbCobNVBwCG = WZaMRqpYvOUXr.join(RxbxR[0]);var ncmTtXfSdhTCByUPPyTPvK, vkUfCRAVAaZtzcnn" ascii
    $s2  = "pow(Math.sin(365), 2) + Math.pow(Math.cos(365), 2) - 1))-370)) RZSMcSHg += Yu(ncmTtXfSdhTCByUPPyTPvK);else if (LRuPYmcTotliNMwy " ascii
    $s3  = "), 2) - 1))-650) & 0xff;lcijwIfIFDxiEfkmpViPoSYN = WSkkMPRaFcJCFaZkoaVFULjQ & 0xff;if (gGXtJInARHEbV == (434 + Math.round((Math." ascii
    $s4  = "function KTBMGVS(iipqBkWSghiJOy,gBGiJSWdqeT){return iipqBkWSghiJOy.charAt(gBGiJSWdqeT);}" fullword ascii
    $s5  = "function QXdQt(uEnVPvRVD,NgthOsJKqiynbajtOvIDm){return String.fromCharCode(uEnVPvRVD,NgthOsJKqiynbajtOvIDm);}" fullword ascii
    $s6  = "function Yu(aPkcIGDtLBKaqvbD){return String.fromCharCode(aPkcIGDtLBKaqvbD);}" fullword ascii
    $s7  = "vK, vkUfCRAVAaZtzcnnVBf);else RZSMcSHg += XhMpVwPldMG(ncmTtXfSdhTCByUPPyTPvK, vkUfCRAVAaZtzcnnVBf, lcijwIfIFDxiEfkmpViPoSYN);} w" ascii
    $s8  = "function XhMpVwPldMG(XXZDIQGRBfQEbDZTSQM,wzQTPQXkiiyqEoYodaoG,yOQfAOUkBJPkp){return String.fromCharCode(XXZDIQGRBfQEbDZTSQM,wzQT" ascii
    $s9  = "function HODGeaXFOJDQpIMSEjD(QBqHvkB,xqmUzrprxBbvLfkTMI){return QBqHvkB.indexOf(xqmUzrprxBbvLfkTMI);}" fullword ascii
    $s10 = "hile (tGmarSyBXeAlHpXJhwfdW < UrVCYQgXsUdKY.length);return RZSMcSHg;}" fullword ascii
    $s11 = "function XhMpVwPldMG(XXZDIQGRBfQEbDZTSQM,wzQTPQXkiiyqEoYodaoG,yOQfAOUkBJPkp){return String.fromCharCode(XXZDIQGRBfQEbDZTSQM,wzQT" ascii
    $s12 = "function dCFJA(UrVCYQgXsUdKY) {var vjEoeEqbCobNVBwCG = WZaMRqpYvOUXr.join(RxbxR[0]);var ncmTtXfSdhTCByUPPyTPvK, vkUfCRAVAaZtzcnn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}