rule sig_20151211_a35d16d38474b633d0622bb8804a3b0e {
  meta:
    description = "datamaliciousorder - file 20151211_a35d16d38474b633d0622bb8804a3b0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f7c85ef5e4a53a00c6003deae4ce25780a968b20e35a7648b1653fd416ef7a5"

  strings:
    $s1  = "function BaIRcsOpRDTDZAeMQ(wNSbf){hNRHetSmgcq= '';FafrQOzfXJo=(-301+301)/43; while(true){if(FafrQOzfXJo >= (-289+509)/110)break;" ascii
    $s2  = "function BaIRcsOpRDTDZAeMQ(wNSbf){hNRHetSmgcq= '';FafrQOzfXJo=(-301+301)/43; while(true){if(FafrQOzfXJo >= (-289+509)/110)break;" ascii
    $s3  = "function qomjEHA(JnmMqXwnljtEMEhoIyuUlULdlPhWkyBopVNU) {return !isNaN(parseFloat(JnmMqXwnljtEMEhoIyuUlULdlPhWkyBopVNU)) && isFin" ascii
    $s4  = "function qomjEHA(JnmMqXwnljtEMEhoIyuUlULdlPhWkyBopVNU) {return !isNaN(parseFloat(JnmMqXwnljtEMEhoIyuUlULdlPhWkyBopVNU)) && isFin" ascii
    $s5  = "tUBlCpXxj[FafrQOzfXJo]=(-492+492)/504; while(true) { if(tUBlCpXxj[FafrQOzfXJo] > wNSbf[FafrQOzfXJo].length-(-682+770)/88) { brea" ascii
    $s6  = "var z=new Array(\"2b\",\"2f\",\"2c\",\"2e\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s7  = "function LYRQTlAugzFPYyKNwNbtGAgmLBZPOAFilYWSRtXLbrqewhBkqVULST(jOukMCuipOBdm,KstGXbyCNSiqVZ){ return UrMXy[bxXuB(jOukMCuipOBdm[" ascii
    $s8  = " abWeP;}function gvsYKKvEyylbPXN(GyMfbpOARfQdkalDH){eval(GyMfbpOARfQdkalDH)}" fullword ascii
    $s9  = "function XVGGBXBacmm(kTCDqsLW,wPmmJH){return kTCDqsLW.split(wPmmJH)}" fullword ascii
    $s10 = "+;}FafrQOzfXJo++;} return hNRHetSmgcq}" fullword ascii
    $s11 = "function LYRQTlAugzFPYyKNwNbtGAgmLBZPOAFilYWSRtXLbrqewhBkqVULST(jOukMCuipOBdm,KstGXbyCNSiqVZ){ return UrMXy[bxXuB(jOukMCuipOBdm[" ascii
    $s12 = "var z=new Array(\"2b\",\"2f\",\"2c\",\"2e\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "var E=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"44\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "var E=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"44\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "function bxXuB(HOHqXReZDmt,TRNTSBxyUafPU,ccnwURjr){FqFR=parseInt(HOHqXReZDmt,TRNTSBxyUafPU);abWeP=FqFR.toString(ccnwURjr);return" ascii
    $s16 = "function bxXuB(HOHqXReZDmt,TRNTSBxyUafPU,ccnwURjr){FqFR=parseInt(HOHqXReZDmt,TRNTSBxyUafPU);abWeP=FqFR.toString(ccnwURjr);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}