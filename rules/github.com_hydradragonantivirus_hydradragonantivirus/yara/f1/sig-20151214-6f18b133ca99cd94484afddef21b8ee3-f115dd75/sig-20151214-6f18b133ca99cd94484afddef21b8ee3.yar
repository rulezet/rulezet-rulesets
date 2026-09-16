rule sig_20151214_6f18b133ca99cd94484afddef21b8ee3 {
  meta:
    description = "datamaliciousorder - file 20151214_6f18b133ca99cd94484afddef21b8ee3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d60df2c73c6ce6ee58ce8de25ce8b06e21f5d11cab938b0d6ab9ee0930cf0f1"

  strings:
    $s1  = "function QfLeyGfqNjNjjVILO(ioilt){dKLuHdERBsn= a[1788];for(koGKKsVSAyc=Math.round((Math.pow(Math.sin(947), 2) + Math.pow(Math.co" ascii
    $s2  = "ath.pow(Math.cos(536), 2) - 1)); while(true) { if(PWVpxsLKm[koGKKsVSAyc] > ioilt[koGKKsVSAyc].length-(-411+434)/23) { break; } i" ascii
    $s3  = "ow(Math.cos(592), 2) - 1)));} PWVpxsLKm[koGKKsVSAyc]++;}} return dKLuHdERBsn}" fullword ascii
    $s4  = "function mVZuVewLkpducGddWgAZWQymeGYtduMPClzSMkPbIXGocdhTDMMFNc(oHiVSaGTaslrQ,ygRxDFUbElhePT){ return OeMVxhg[ycuAbBhQ[fPZEr(oHi" ascii
    $s5  = "function mVZuVewLkpducGddWgAZWQymeGYtduMPClzSMkPbIXGocdhTDMMFNc(oHiVSaGTaslrQ,ygRxDFUbElhePT){ return OeMVxhg[ycuAbBhQ[fPZEr(oHi" ascii
    $s6  = "function QfLeyGfqNjNjjVILO(ioilt){dKLuHdERBsn= a[1788];for(koGKKsVSAyc=Math.round((Math.pow(Math.sin(947), 2) + Math.pow(Math.co" ascii
    $s7  = "KEwG)) {return (String.fromCharCode(qVTUpRpGbQnyKEwG) + String.fromCharCode((43413+75)/906));}}" fullword ascii
    $s8  = "function o(lvHMHRLvwTRi,vkRMmVuQXoJvUZ){lvHMHRLvwTRi.push(vkRMmVuQXoJvUZ);}function G8(qVTUpRpGbQnyKEwG){if(RoDyBkB(qVTUpRpGbQny" ascii
    $s9  = "function RoDyBkB(KyiZRbtyniuGTIcMAVPvnsteZzUJZvYGAgBD) {return !isNaN(parseFloat(KyiZRbtyniuGTIcMAVPvnsteZzUJZvYGAgBD)) && isFin" ascii
    $s10 = "function RoDyBkB(KyiZRbtyniuGTIcMAVPvnsteZzUJZvYGAgBD) {return !isNaN(parseFloat(KyiZRbtyniuGTIcMAVPvnsteZzUJZvYGAgBD)) && isFin" ascii
    $s11 = "function eglhJRZIxEj(XMBGpDdX,vVjqba){return XMBGpDdX.split(vVjqba)}" fullword ascii
    $s12 = "function fPZEr(xsZcObJdmiZ,ttOezQGKyxwfS,FDmUHepx){FfSb=parseInt(xsZcObJdmiZ,ttOezQGKyxwfS);rHBtA=FfSb.toString(FDmUHepx);return" ascii
    $s13 = "var a=new Array();" fullword ascii
    $s14 = "function o(lvHMHRLvwTRi,vkRMmVuQXoJvUZ){lvHMHRLvwTRi.push(vkRMmVuQXoJvUZ);}function G8(qVTUpRpGbQnyKEwG){if(RoDyBkB(qVTUpRpGbQny" ascii
    $s15 = "function fPZEr(xsZcObJdmiZ,ttOezQGKyxwfS,FDmUHepx){FfSb=parseInt(xsZcObJdmiZ,ttOezQGKyxwfS);rHBtA=FfSb.toString(FDmUHepx);return" ascii
    $s16 = " rHBtA;}function VyZnTKZHUcyVHZm(EYIIAIdSSlEAiCDNh,GFGvrRYqnHIerJvKmQolxtcLcDbZhqrPED,iIoIeWaEJNRblwpXNxHVcIUmqVuisYPkpox){eval(" ascii
    $s17 = "function VyZnTKZHUcyVHZm(EYIIAIdSSlEAiCDNh){eval(EYIIAIdSSlEAiCDNh)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}