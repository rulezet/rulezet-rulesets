rule sig_20160323_f44a337ebf8d30c5348f8e5d41c91d95 {
  meta:
    description = "datamaliciousorder - file 20160323_f44a337ebf8d30c5348f8e5d41c91d95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ac8d681765ec9efb5d6d31d6ed80f989b67c23b21344bcb1c59c8f152314779"

  strings:
    $s1  = "return WScript.CreateObject(swlss);" fullword ascii
    $s2  = "var PW = true  , GIfJ = nei[7] + nei[9] + nei[11];" fullword ascii
    $s3  = "return IJXezmi[0] + IJXezmi[2] + IJXezmi[4] + \".F\" + IJXezmi[7] + IJXezmi[9] + IJXezmi[12] + IJXezmi[14];" fullword ascii
    $s4  = "var IJXezmi = ZDWOf(pDbqGlvEko+\" \"+\"System cC KxyrC Obj kQooNK ect BeZGNFM GMKnE\", \" \");" fullword ascii
    $s5  = "RuBw.open(lSRkn,kjcNd,false);" fullword ascii
    $s6  = "var nei = (\"2.XMLHTTP dcKxRSt wVump XML ream St FZLUcQvK AD OUKOtxi O Pkdj D\").split(\" \");" fullword ascii
    $s7  = "if(n>=J.length) {break;}" fullword ascii
    $s8  = "return dwhRn;" fullword ascii
    $s9  = "function tfeWL(KpRJPY) {" fullword ascii
    $s10 = "if (BGsOU > 198827-315){return true;} else {return false;}" fullword ascii
    $s11 = "function EGUGvXyq(Hpn) {" fullword ascii
    $s12 = "function agpR(SgWze) {" fullword ascii
    $s13 = "function pgdI(iXDAx) {" fullword ascii
    $s14 = "tMM = n; break; " fullword ascii
    $s15 = "function eqhL(nSjeB) {" fullword ascii
    $s16 = "return iGOYdtl(Mp,YrLdX[852-846]+YrLdX[766-759]+YrLdX[537-529]);" fullword ascii
    $s17 = "if (v >= SgWze.length) {break;}" fullword ascii
    $s18 = "function iGOYdtl(jnpg,ROqgD) {" fullword ascii
    $s19 = "function GCNz(XdnxS) {" fullword ascii
    $s20 = "function jrLK(TrEAw,aFiPp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}