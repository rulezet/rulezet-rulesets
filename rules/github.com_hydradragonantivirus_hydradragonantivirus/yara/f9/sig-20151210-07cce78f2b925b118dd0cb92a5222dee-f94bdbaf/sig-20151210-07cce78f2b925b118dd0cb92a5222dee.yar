rule sig_20151210_07cce78f2b925b118dd0cb92a5222dee {
  meta:
    description = "datamaliciousorder - file 20151210_07cce78f2b925b118dd0cb92a5222dee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bd88af5e244f7f73f09a26c72006dd8a3c551fb2565a7e55415a51e6481c1ed"

  strings:
    $s1  = "function wPRkHmG(cejTmOowsGnppYfimDxIPHecfZnCMLlGvdEm) {return !isNaN(parseFloat(cejTmOowsGnppYfimDxIPHecfZnCMLlGvdEm)) && isFin" ascii
    $s2  = "function wPRkHmG(cejTmOowsGnppYfimDxIPHecfZnCMLlGvdEm) {return !isNaN(parseFloat(cejTmOowsGnppYfimDxIPHecfZnCMLlGvdEm)) && isFin" ascii
    $s3  = "function fbTrs(jmKUUlYhUXm,KIgkUcgyFFMju,wcTElQzA){SrWH=parseInt(jmKUUlYhUXm,KIgkUcgyFFMju);yIsnv=SrWH.toString(wcTElQzA);return" ascii
    $s4  = "function oJrMkKgFtbOOXpeeo(vvtCy){ZBqMECIGyRL= '';for(KWcQPAuBlfH=(-788+788)/755; KWcQPAuBlfH < (955+911)/933; KWcQPAuBlfH++) {t" ascii
    $s5  = "function fbTrs(jmKUUlYhUXm,KIgkUcgyFFMju,wcTElQzA){SrWH=parseInt(jmKUUlYhUXm,KIgkUcgyFFMju);yIsnv=SrWH.toString(wcTElQzA);return" ascii
    $s6  = " yIsnv;}function CiWfjozBvLYlZgw(kqZWXcHLLqOPaHjBc){eval(kqZWXcHLLqOPaHjBc)}" fullword ascii
    $s7  = "nMOWuVb=(-977+977)/743;while(true){if(nMOWuVb>=(109722+614)/862){break;}ywtpYkMtEGzon[nMOWuVb]=String.fromCharCode(nMOWuVb);nMOW" ascii
    $s8  = "function mxpACCbqYRV(FlLPIvUT,uBrHxb){return FlLPIvUT.split(uBrHxb)}" fullword ascii
    $s9  = "mAGDGknS[KWcQPAuBlfH]=(-779+779)/965; while(true) { if(tmAGDGknS[KWcQPAuBlfH] > vvtCy[KWcQPAuBlfH].length-(384+578)/962) { break" ascii
    $s10 = "function UvoUVoDVunaorBaymxkgenEHDvvShMoSFoYZPWHmobFLGYPKSTTUzY(HxnMCTTPKyNhm,yLaZCepSSDUtNd){ return ywtpYkMtEGzon[fbTrs(HxnMCT" ascii
    $s11 = "+;}} return ZBqMECIGyRL}" fullword ascii
    $s12 = "function UvoUVoDVunaorBaymxkgenEHDvvShMoSFoYZPWHmobFLGYPKSTTUzY(HxnMCTTPKyNhm,yLaZCepSSDUtNd){ return ywtpYkMtEGzon[fbTrs(HxnMCT" ascii
    $s13 = "function oJrMkKgFtbOOXpeeo(vvtCy){ZBqMECIGyRL= '';for(KWcQPAuBlfH=(-788+788)/755; KWcQPAuBlfH < (955+911)/933; KWcQPAuBlfH++) {t" ascii
    $s14 = "nMOWuVb=(-977+977)/743;while(true){if(nMOWuVb>=(109722+614)/862){break;}ywtpYkMtEGzon[nMOWuVb]=String.fromCharCode(nMOWuVb);nMOW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}