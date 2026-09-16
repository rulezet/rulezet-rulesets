rule sig_20151210_f43d2b9da924ebff51fbfa9a324195ad {
  meta:
    description = "datamaliciousorder - file 20151210_f43d2b9da924ebff51fbfa9a324195ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "094348c61d87cdd59ede17374d7cb88693b6751db33b34f6d89e575228abb090"

  strings:
    $s1  = "function LAPmEJW(tNPHyaqNVqGTLiMRGZHpiDbQVqHVTvYQKvkD) {return !isNaN(parseFloat(tNPHyaqNVqGTLiMRGZHpiDbQVqHVTvYQKvkD)) && isFin" ascii
    $s2  = "function LAPmEJW(tNPHyaqNVqGTLiMRGZHpiDbQVqHVTvYQKvkD) {return !isNaN(parseFloat(tNPHyaqNVqGTLiMRGZHpiDbQVqHVTvYQKvkD)) && isFin" ascii
    $s3  = "function tChcORGHawturbZpK(tRahb){kDPoorzdTQj= '';for(ARuyxfUvRJV=(-471+471)/923; ARuyxfUvRJV < (335+461)/398; ARuyxfUvRJV++) {d" ascii
    $s4  = "function LgpXv(QJszXnukXxN,UsCNJXKgjVCPM,qoFnTcqU){LGNC=parseInt(QJszXnukXxN,UsCNJXKgjVCPM);Ygdip=LGNC.toString(qoFnTcqU);return" ascii
    $s5  = "function tChcORGHawturbZpK(tRahb){kDPoorzdTQj= '';for(ARuyxfUvRJV=(-471+471)/923; ARuyxfUvRJV < (335+461)/398; ARuyxfUvRJV++) {d" ascii
    $s6  = "BjoOZgt=(-843+843)/327;while(true){if(BjoOZgt>=(26113+255)/206){break;}bfOyFEGnyXoef[BjoOZgt]=String.fromCharCode(BjoOZgt);BjoOZ" ascii
    $s7  = "function ItfdtwxKVSywhfXweJmPkNKyGcLGXDcFJNSXPLzMOpKDhtCObMCvPW(mIDDfEznIGoSw,HhxzIsIHaZjFfl){ return bfOyFEGnyXoef[LgpXv(mIDDfE" ascii
    $s8  = " Ygdip;}function ijAOUPudCSihbvR(zmGDuukMBvOtVQkqp){eval(zmGDuukMBvOtVQkqp)}" fullword ascii
    $s9  = "function QvzItZBMfRu(SmutMGuM,lRZosY){return SmutMGuM.split(lRZosY)}" fullword ascii
    $s10 = "function LgpXv(QJszXnukXxN,UsCNJXKgjVCPM,qoFnTcqU){LGNC=parseInt(QJszXnukXxN,UsCNJXKgjVCPM);Ygdip=LGNC.toString(qoFnTcqU);return" ascii
    $s11 = "}} return kDPoorzdTQj}" fullword ascii
    $s12 = "BjoOZgt=(-843+843)/327;while(true){if(BjoOZgt>=(26113+255)/206){break;}bfOyFEGnyXoef[BjoOZgt]=String.fromCharCode(BjoOZgt);BjoOZ" ascii
    $s13 = "JKkzCWOV[ARuyxfUvRJV]=(-917+917)/765; while(true) { if(dJKkzCWOV[ARuyxfUvRJV] > tRahb[ARuyxfUvRJV].length-(440+457)/897) { break" ascii
    $s14 = "function ItfdtwxKVSywhfXweJmPkNKyGcLGXDcFJNSXPLzMOpKDhtCObMCvPW(mIDDfEznIGoSw,HhxzIsIHaZjFfl){ return bfOyFEGnyXoef[LgpXv(mIDDfE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}