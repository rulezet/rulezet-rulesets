rule sig_20151209_9b444cdcf15893f490d4eb8347bb347b {
  meta:
    description = "datamaliciousorder - file 20151209_9b444cdcf15893f490d4eb8347bb347b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89960fdc99d3332b38b1750947f1463d4ee0d2c9b06afae9b8b311e076956537"

  strings:
    $s1  = "function QCkbrcBiNBAIGBZaI(kFLqg){LIsvkyaimLz= '';for(vksYFZxOkOH=(-461+461)/662; vksYFZxOkOH < (273+247)/260; vksYFZxOkOH++) {I" ascii
    $s2  = "function QCkbrcBiNBAIGBZaI(kFLqg){LIsvkyaimLz= '';for(vksYFZxOkOH=(-461+461)/662; vksYFZxOkOH < (273+247)/260; vksYFZxOkOH++) {I" ascii
    $s3  = "function OVvZhbE(RiTEaBRTBZuqFurKaHncnNPCnmPSEjurvdKH) {return !isNaN(parseFloat(RiTEaBRTBZuqFurKaHncnNPCnmPSEjurvdKH)) && isFin" ascii
    $s4  = "function OVvZhbE(RiTEaBRTBZuqFurKaHncnNPCnmPSEjurvdKH) {return !isNaN(parseFloat(RiTEaBRTBZuqFurKaHncnNPCnmPSEjurvdKH)) && isFin" ascii
    $s5  = "function csPYEwIUkyzaAWeKijVQvQygBgcNoRnqyhofXBaDwUdPFYDmDtaKIl(wpsKwzzvcKwVK,AvOUwxnrCAYXBy){ return RJjww[RQshh(wpsKwzzvcKwVK[" ascii
    $s6  = "function csPYEwIUkyzaAWeKijVQvQygBgcNoRnqyhofXBaDwUdPFYDmDtaKIl(wpsKwzzvcKwVK,AvOUwxnrCAYXBy){ return RJjww[RQshh(wpsKwzzvcKwVK[" ascii
    $s7  = "function EQOgAjBlzST(MioqpBdR,IJGfZL){return MioqpBdR.split(IJGfZL)}" fullword ascii
    $s8  = "function RQshh(jVKRXVaVSSJ,zaebmXUdYYaNL,HTVDUnVC){bUMn=parseInt(jVKRXVaVSSJ,zaebmXUdYYaNL);VfzFo=bUMn.toString(HTVDUnVC);return" ascii
    $s9  = " VfzFo;}function vYzdSUEYIabUuQi(mTQrywpZYARZhXLgB){eval(mTQrywpZYARZhXLgB)}" fullword ascii
    $s10 = "function RQshh(jVKRXVaVSSJ,zaebmXUdYYaNL,HTVDUnVC){bUMn=parseInt(jVKRXVaVSSJ,zaebmXUdYYaNL);VfzFo=bUMn.toString(HTVDUnVC);return" ascii
    $s11 = "lFAPwAjc[vksYFZxOkOH]=(-962+962)/382; while(true) { if(IlFAPwAjc[vksYFZxOkOH] > kFLqg[vksYFZxOkOH].length-(345+498)/843) { break" ascii
    $s12 = "+;}} return LIsvkyaimLz}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}