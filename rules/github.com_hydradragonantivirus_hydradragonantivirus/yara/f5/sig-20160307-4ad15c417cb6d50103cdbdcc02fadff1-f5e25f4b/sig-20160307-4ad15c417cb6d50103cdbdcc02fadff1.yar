rule sig_20160307_4ad15c417cb6d50103cdbdcc02fadff1 {
  meta:
    description = "datamaliciousorder - file 20160307_4ad15c417cb6d50103cdbdcc02fadff1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d3b1f2e46df0682762ba2df01c20543931b404b985394904f23f16e27decdf0"

  strings:
    $s1  = "var tW = true  , xIec = pPW[7] + pPW[9] + pPW[11];" fullword ascii
    $s2  = "return xxhpBsp[0] + xxhpBsp[2] + xxhpBsp[4] + \".F\" + xxhpBsp[7] + xxhpBsp[9] + xxhpBsp[12] + xxhpBsp[14];" fullword ascii
    $s3  = "var pPW = (\"2.XMLHTTP ZhamwaV pocuE XML ream St qTLKgGWE AD gXhvWkQ O hEJJ D\").split(\" \");" fullword ascii
    $s4  = "var xxhpBsp = \"Sc FyjXQxj r IbCjUYygo ipting lMZLGmh tUj ile UkOOqsepkaunQx System QN SgdcW Obj FKvcXU ect ntNVHXX\".split(\" " ascii
    $s5  = "KhfzI.open(WqTYe,AmwuG,false);" fullword ascii
    $s6  = "if(X>=A.length) {break;}" fullword ascii
    $s7  = "function XSST(OIiPp) {" fullword ascii
    $s8  = "function uMAWBGHYg(aQWvQPobydO) {" fullword ascii
    $s9  = "return new ActiveXObject(sfupCj);" fullword ascii
    $s10 = "function sjFr(rfcjV,pdGdR) {" fullword ascii
    $s11 = "if (P >= arWTP.length) {break;}" fullword ascii
    $s12 = "function ivZXIeHB() {" fullword ascii
    $s13 = "function oXkXR(sfupCj) {" fullword ascii
    $s14 = "return HopHE;" fullword ascii
    $s15 = "return eRPHc.status;" fullword ascii
    $s16 = "function FBiY(arWTP) {" fullword ascii
    $s17 = "function IVjtjliZ(ICJ) {" fullword ascii
    $s18 = "function odYs(KhfzI,AmwuG,WqTYe) {" fullword ascii
    $s19 = "function NmKk(xHmom) {" fullword ascii
    $s20 = "function lbTKWda(zBhQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}