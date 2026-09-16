rule sig_20151214_0104360f9422f08c2be88b102496f1b7 {
  meta:
    description = "datamaliciousorder - file 20151214_0104360f9422f08c2be88b102496f1b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c12417288116ce0b66af38f38fe2c447d6c06d1ce88979542ac289f21668747"

  strings:
    $s1  = ".pow(Math.cos(295), 2) - 1)); while(true) { if(eNlFmxQyZ[aFuaXxwjwEk] > lJvlR[aFuaXxwjwEk].length-(-433+625)/192) { break; } if " ascii
    $s2  = "5), 2) - 1)); aFuaXxwjwEk < (1166+626)/896; aFuaXxwjwEk++) {eNlFmxQyZ[aFuaXxwjwEk]=Math.round((Math.pow(Math.sin(295), 2) + Math" ascii
    $s3  = "function uLPPosDdZLTBNmsFf(lJvlR){XGRRDyFRdoH= c[1741];for(aFuaXxwjwEk=Math.round((Math.pow(Math.sin(5), 2) + Math.pow(Math.cos(" ascii
    $s4  = "(Math.cos(495), 2) - 1)));} eNlFmxQyZ[aFuaXxwjwEk]++;}} return XGRRDyFRdoH}" fullword ascii
    $s5  = "function uLPPosDdZLTBNmsFf(lJvlR){XGRRDyFRdoH= c[1741];for(aFuaXxwjwEk=Math.round((Math.pow(Math.sin(5), 2) + Math.pow(Math.cos(" ascii
    $s6  = "oFBg)) {return (String.fromCharCode(HQPYpQxLyWikoFBg) + String.fromCharCode((18706+110)/294));}}" fullword ascii
    $s7  = "function j(uZRRmDSUmcMi,bpAaKxpMWiBFVx){uZRRmDSUmcMi.push(bpAaKxpMWiBFVx);}function e7(HQPYpQxLyWikoFBg){if(FHicjqY(HQPYpQxLyWik" ascii
    $s8  = "function FHicjqY(jsjtGJYwIUQedHReLtltbKtXAQlLkzqOPhhF) {return !isNaN(parseFloat(jsjtGJYwIUQedHReLtltbKtXAQlLkzqOPhhF)) && isFin" ascii
    $s9  = "function FHicjqY(jsjtGJYwIUQedHReLtltbKtXAQlLkzqOPhhF) {return !isNaN(parseFloat(jsjtGJYwIUQedHReLtltbKtXAQlLkzqOPhhF)) && isFin" ascii
    $s10 = "function GuoQsbSuTrpYhnFGAcCTBnEdMrmvVYeCzJsYaIdzQuovOZwFZCnklF(IryxSazIvZmfu,rDICwjMkbOIrhu){ return ZjGxguo[jLEwDQqF[gMYCU(Iry" ascii
    $s11 = "var c=new Array();" fullword ascii
    $s12 = "function j(uZRRmDSUmcMi,bpAaKxpMWiBFVx){uZRRmDSUmcMi.push(bpAaKxpMWiBFVx);}function e7(HQPYpQxLyWikoFBg){if(FHicjqY(HQPYpQxLyWik" ascii
    $s13 = "function GuoQsbSuTrpYhnFGAcCTBnEdMrmvVYeCzJsYaIdzQuovOZwFZCnklF(IryxSazIvZmfu,rDICwjMkbOIrhu){ return ZjGxguo[jLEwDQqF[gMYCU(Iry" ascii
    $s14 = "function gMYCU(AuoGOsjNgWm,zAHtnKoTKSmCI,NDiUcCOR){TIqc=parseInt(AuoGOsjNgWm,zAHtnKoTKSmCI);hNFQC=TIqc.toString(NDiUcCOR);return" ascii
    $s15 = " hNFQC;}function piSEVPVENmXAXsN(ujECKEfRHONMAeYjw,synPgDuTuzwWJztFuFdBahFgzePmbfRhti,FeUlIxgwezIlBsHgbwtmbggRXfFFKEqmFtJ){eval(" ascii
    $s16 = "function piSEVPVENmXAXsN(ujECKEfRHONMAeYjw){eval(ujECKEfRHONMAeYjw)}" fullword ascii
    $s17 = "function gMYCU(AuoGOsjNgWm,zAHtnKoTKSmCI,NDiUcCOR){TIqc=parseInt(AuoGOsjNgWm,zAHtnKoTKSmCI);hNFQC=TIqc.toString(NDiUcCOR);return" ascii
    $s18 = "function CfwHvDRxnlP(WbLdCaFh,VAImxC){return WbLdCaFh.split(VAImxC)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}