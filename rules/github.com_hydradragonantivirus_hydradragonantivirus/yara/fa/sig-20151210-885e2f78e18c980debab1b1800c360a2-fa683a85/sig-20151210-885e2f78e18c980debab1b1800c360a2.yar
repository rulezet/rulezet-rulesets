rule sig_20151210_885e2f78e18c980debab1b1800c360a2 {
  meta:
    description = "datamaliciousorder - file 20151210_885e2f78e18c980debab1b1800c360a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "598f0c485277049e77b4f0c5e961b962565a67142d698e74d05cfc8c72166808"

  strings:
    $s1  = "function BDaTmXa(JgUgDDdsgczTxKYDWfEqjLMjdCrIFBlOhPOx) {return !isNaN(parseFloat(JgUgDDdsgczTxKYDWfEqjLMjdCrIFBlOhPOx)) && isFin" ascii
    $s2  = "function BDaTmXa(JgUgDDdsgczTxKYDWfEqjLMjdCrIFBlOhPOx) {return !isNaN(parseFloat(JgUgDDdsgczTxKYDWfEqjLMjdCrIFBlOhPOx)) && isFin" ascii
    $s3  = "function LAfntnhCzqBYMToxG(MYjtS){ifIzzgKmupm= '';for(dktnFQghyBW=(-517+517)/449; dktnFQghyBW < (646+858)/752; dktnFQghyBW++) {B" ascii
    $s4  = "function FYttX(bsvJTLubUWD,dfwZYdadxoYFx,HuIvHgsw){amVB=parseInt(bsvJTLubUWD,dfwZYdadxoYFx);tRLjj=amVB.toString(HuIvHgsw);return" ascii
    $s5  = "UXfBDjfA[dktnFQghyBW]=(-172+172)/621; while(true) { if(BUXfBDjfA[dktnFQghyBW] > MYjtS[dktnFQghyBW].length-(-355+801)/446) { brea" ascii
    $s6  = " tRLjj;}function SVYNvhVsYzhloBd(szvNIApCSeJkngmqt){eval(szvNIApCSeJkngmqt)}" fullword ascii
    $s7  = "function KlaGJnfMzUnnqrrCNOvDFSkhmLueXnlNtFfiTZdegrFfmpSSLgVHLk(JLyFLlTRFKheZ,lwPglYNQGQxLae){ return iUWNp[FYttX(JLyFLlTRFKheZ[" ascii
    $s8  = "function PmomelRVwPS(wvaJVQes,hftFGf){return wvaJVQes.split(hftFGf)}" fullword ascii
    $s9  = "function FYttX(bsvJTLubUWD,dfwZYdadxoYFx,HuIvHgsw){amVB=parseInt(bsvJTLubUWD,dfwZYdadxoYFx);tRLjj=amVB.toString(HuIvHgsw);return" ascii
    $s10 = "function LAfntnhCzqBYMToxG(MYjtS){ifIzzgKmupm= '';for(dktnFQghyBW=(-517+517)/449; dktnFQghyBW < (646+858)/752; dktnFQghyBW++) {B" ascii
    $s11 = "function KlaGJnfMzUnnqrrCNOvDFSkhmLueXnlNtFfiTZdegrFfmpSSLgVHLk(JLyFLlTRFKheZ,lwPglYNQGQxLae){ return iUWNp[FYttX(JLyFLlTRFKheZ[" ascii
    $s12 = ";}} return ifIzzgKmupm}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}