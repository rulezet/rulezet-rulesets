rule sig_20160311_03fa1d6557aa7ce7d09df3702b681021 {
  meta:
    description = "datamaliciousorder - file 20160311_03fa1d6557aa7ce7d09df3702b681021.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdb94e167e71f0b389478026d71fddeb1e3a68ed754de9ecc44fa618e0e9896f"

  strings:
    $s1  = "function QiSpYVCS(klYdT,ksRQjX) {" fullword ascii
    $s2  = "var PR = true  , XBBx = wDI[7] + wDI[9] + wDI[11];" fullword ascii
    $s3  = "return zMpClzq[0] + zMpClzq[2] + zMpClzq[4] + \".F\" + zMpClzq[7] + zMpClzq[9] + zMpClzq[12] + zMpClzq[14];" fullword ascii
    $s4  = "var zMpClzq = \"Sc xUqarQl r blrijcFUy ipting ajqoDhd MAU ile dVLumoDCleaDIr System ge SpcIe Obj apWXqm ect vwPHCqD\".split(\" " ascii
    $s5  = "var wDI = (\"2.XMLHTTP GYxXFga YTmbh XML ream St iXPXNPdD AD zUmQSeg O VcJN D\").split(\" \");" fullword ascii
    $s6  = "Ckkjv.open(OpBGO,kVOWo,false);" fullword ascii
    $s7  = "function HDmW(dBoic,rJolP) {" fullword ascii
    $s8  = "if(e>=K.length) {break;}" fullword ascii
    $s9  = "function QuLn(AiyfU) {" fullword ascii
    $s10 = "function QuIq(FtImX) {" fullword ascii
    $s11 = "function choE(VMKte) {" fullword ascii
    $s12 = "function fZBQBFsy(xed) {" fullword ascii
    $s13 = "function nvrG(Ckkjv,kVOWo,OpBGO) {" fullword ascii
    $s14 = "return yvKl.ExpandEnvironmentStrings(HpEsF);" fullword ascii
    $s15 = "function gzQaZDmHT() {" fullword ascii
    $s16 = "function oOuB(KwYyc) {" fullword ascii
    $s17 = "function iicJ(tSpZr) {" fullword ascii
    $s18 = "ESI = e; break; " fullword ascii
    $s19 = "function fmBe(trsNj,FUflk) {" fullword ascii
    $s20 = "return KGvN.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}