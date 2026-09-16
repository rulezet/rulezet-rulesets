rule sig_20151219_445f2cb73a4ec43b51212df640f56288 {
  meta:
    description = "datamaliciousorder - file 20151219_445f2cb73a4ec43b51212df640f56288.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b3ed210596a3330a2f85b9802a33416df8355aa4e4040dbf4f6a6b514781e85"

  strings:
    $s1  = "function AnaaQswJFQylXmwXc(GIlHY){QlOKHzMXvsI= '';for(KTGfCeUwmbq=Math.round((Math.pow(Math.sin(857), 2) + Math.pow(Math.cos(857" ascii
    $s2  = "function AnaaQswJFQylXmwXc(GIlHY){QlOKHzMXvsI= '';for(KTGfCeUwmbq=Math.round((Math.pow(Math.sin(857), 2) + Math.pow(Math.cos(857" ascii
    $s3  = "function hqWFoVKAwGIGMSX(XagXhHowYHLBuVvIl,xIxzlnLIstBbJsUyxXFOHKstMfoagtuAut,FklHxDEgjdJsKFGzhPEQJLNnUuNuywRIiXJ){eval(XagXhHow" ascii
    $s4  = "function ifWBSlgrWEaa(DBBLTWPvgJTLx) {return isFinite(DBBLTWPvgJTLx);}" fullword ascii
    $s5  = "function LJfNF(ECKaSMWxsAv,cnzHkqiVrOIDn,qqUHamoS){hbiY=QCJzTnMyhyWsHgzAV(ECKaSMWxsAv,cnzHkqiVrOIDn);qbqgA=hbiY.toString(qqUHamo" ascii
    $s6  = "function mjGSJtjYbcd(GSefZUysfzKibt) {return isNaN(GSefZUysfzKibt);}" fullword ascii
    $s7  = "S);return qbqgA;}" fullword ascii
    $s8  = "ICDXKycP,KTGfCeUwmbq);} return QlOKHzMXvsI}" fullword ascii
    $s9  = "function LJfNF(ECKaSMWxsAv,cnzHkqiVrOIDn,qqUHamoS){hbiY=QCJzTnMyhyWsHgzAV(ECKaSMWxsAv,cnzHkqiVrOIDn);qbqgA=hbiY.toString(qqUHamo" ascii
    $s10 = "function P(izItqXkrtVbx,lyIyLfLEIFZyHI){izItqXkrtVbx.push(lyIyLfLEIFZyHI);}" fullword ascii
    $s11 = "function QCJzTnMyhyWsHgzAV(JkrWgixNfd,lKayXxWtmB) {return parseInt(JkrWgixNfd,lKayXxWtmB);}" fullword ascii
    $s12 = "function hqWFoVKAwGIGMSX(XagXhHowYHLBuVvIl,xIxzlnLIstBbJsUyxXFOHKstMfoagtuAut,FklHxDEgjdJsKFGzhPEQJLNnUuNuywRIiXJ){eval(XagXhHow" ascii
    $s13 = "function f(gSUrLMcBOJkAnm,aGVghfgtbrRsP,kXAafWoVQmp) {gSUrLMcBOJkAnm[aGVghfgtbrRsP]=kXAafWoVQmp;}" fullword ascii
    $s14 = "function YfLlXOu(AalkkeGtHiFtkETmDRiGsMzyhExKmAApcnkD) {return !mjGSJtjYbcd(whVpnCAGzOQETJD(AalkkeGtHiFtkETmDRiGsMzyhExKmAApcnkD" ascii
    $s15 = "function YfLlXOu(AalkkeGtHiFtkETmDRiGsMzyhExKmAApcnkD) {return !mjGSJtjYbcd(whVpnCAGzOQETJD(AalkkeGtHiFtkETmDRiGsMzyhExKmAApcnkD" ascii
    $s16 = "function YYYSewLdVhQnEkSOZHVYLpHmYwKoDaKAjGBowPWjqKnkNyTFGUHDsh(DjPCupMBowRXR,WHAKCWszpfDDEY){ return OazMwGp[ACaUqbRP[LJfNF(DjP" ascii
    $s17 = "function whVpnCAGzOQETJD(bUKRqBbkFrQyGahpHAE) {return parseFloat(bUKRqBbkFrQyGahpHAE);}" fullword ascii
    $s18 = "function YYYSewLdVhQnEkSOZHVYLpHmYwKoDaKAjGBowPWjqKnkNyTFGUHDsh(DjPCupMBowRXR,WHAKCWszpfDDEY){ return OazMwGp[ACaUqbRP[LJfNF(DjP" ascii

  condition:
    uint16(0) == 0x4341 and
    8 of them
}