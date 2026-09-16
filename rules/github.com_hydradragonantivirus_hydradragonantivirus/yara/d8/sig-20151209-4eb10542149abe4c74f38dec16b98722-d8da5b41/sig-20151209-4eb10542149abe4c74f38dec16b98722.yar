rule sig_20151209_4eb10542149abe4c74f38dec16b98722 {
  meta:
    description = "datamaliciousorder - file 20151209_4eb10542149abe4c74f38dec16b98722.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3abc38d85e57ed149d482d54165768bc56a6dba5e3100cd4f20651b58936d7f1"

  strings:
    $s1  = "function wKAnhGA(bVNyNIGaxLldKYPkcIjcbvtOGCHWZldtBneM) {return !isNaN(parseFloat(bVNyNIGaxLldKYPkcIjcbvtOGCHWZldtBneM)) && isFin" ascii
    $s2  = "function wKAnhGA(bVNyNIGaxLldKYPkcIjcbvtOGCHWZldtBneM) {return !isNaN(parseFloat(bVNyNIGaxLldKYPkcIjcbvtOGCHWZldtBneM)) && isFin" ascii
    $s3  = " FaIWt;}function PuLVcGeVOmDYAhb(WJBccHdUCHZDCnbRn){eval(WJBccHdUCHZDCnbRn)}" fullword ascii
    $s4  = "function JurgMjDPvkrWMpByoVNetZcXguodUVyWBBCoAUhlcmPTBBZBulFyYz(eGhQTHGnlOKGS,fQUzTrkJWztCjC){ return gpoVC[PFFYA(eGhQTHGnlOKGS[" ascii
    $s5  = "dLqfohnv[ZlepsFbWKfz]=(-976+976)/36; while(true) { if(QdLqfohnv[ZlepsFbWKfz] > RjjjF[ZlepsFbWKfz].length-(-569+732)/163) { break" ascii
    $s6  = "+;}} return wZOUrAKFJOa}" fullword ascii
    $s7  = "function PFFYA(hbqwhYLsOur,awzZHmpUskulN,fZgZNipU){vuon=parseInt(hbqwhYLsOur,awzZHmpUskulN);FaIWt=vuon.toString(fZgZNipU);return" ascii
    $s8  = "function TzEKNXkIZtVEiHAee(RjjjF){wZOUrAKFJOa= '';for(ZlepsFbWKfz=(-367+367)/672; ZlepsFbWKfz < (704+484)/594; ZlepsFbWKfz++) {Q" ascii
    $s9  = "function HIyGrRYxVzF(OvZuvqSv,nwsxpC){return OvZuvqSv.split(nwsxpC)}" fullword ascii
    $s10 = "function JurgMjDPvkrWMpByoVNetZcXguodUVyWBBCoAUhlcmPTBBZBulFyYz(eGhQTHGnlOKGS,fQUzTrkJWztCjC){ return gpoVC[PFFYA(eGhQTHGnlOKGS[" ascii
    $s11 = "function TzEKNXkIZtVEiHAee(RjjjF){wZOUrAKFJOa= '';for(ZlepsFbWKfz=(-367+367)/672; ZlepsFbWKfz < (704+484)/594; ZlepsFbWKfz++) {Q" ascii
    $s12 = "function PFFYA(hbqwhYLsOur,awzZHmpUskulN,fZgZNipU){vuon=parseInt(hbqwhYLsOur,awzZHmpUskulN);FaIWt=vuon.toString(fZgZNipU);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}