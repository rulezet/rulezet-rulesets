rule sig_20160310_49409e410252b00263a8f0637ef68f84 {
  meta:
    description = "datamaliciousorder - file 20160310_49409e410252b00263a8f0637ef68f84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d5761d1984275a711185b00b90398c203722b49729401227d4f72c0448e6c50"

  strings:
    $s1  = "return EuqYKfI[0] + EuqYKfI[2] + EuqYKfI[4] + \".F\" + EuqYKfI[7] + EuqYKfI[9] + EuqYKfI[12] + EuqYKfI[14];" fullword ascii
    $s2  = "var yT = true  , ddoq = nbs[7] + nbs[9] + nbs[11];" fullword ascii
    $s3  = "lkRxv.open(LZmfw,xatHW,false);" fullword ascii
    $s4  = "var nbs = (\"2.XMLHTTP mxmAtyr vrGvj XML ream St asIElMlo AD pPLVAEd O dAsc D\").split(\" \");" fullword ascii
    $s5  = "if (FolQr > 167772-755){return true;} else {return false;}" fullword ascii
    $s6  = "function LugSK(ugvZEC) {" fullword ascii
    $s7  = "function HXrC(BaMuA) {" fullword ascii
    $s8  = "if (vdxWW == 554-354){return true;} else {return false;}" fullword ascii
    $s9  = "function WTtx(xpgud) {" fullword ascii
    $s10 = "function xAQF(kBMtp) {" fullword ascii
    $s11 = "function ltEpz(yWzZhS) {" fullword ascii
    $s12 = "function tBIMLuk(XIQE) {" fullword ascii
    $s13 = "function aAflVoUm(SWa) {" fullword ascii
    $s14 = "return XIQE.responseBody;" fullword ascii
    $s15 = "function bUJmswSdw(OKFtD,tCtaM,vQOCX,WXdO) {" fullword ascii
    $s16 = "return BaMuA.status;" fullword ascii
    $s17 = "return IAUG.ExpandEnvironmentStrings(snXfh);" fullword ascii
    $s18 = "function rDnn(ykGPt) {" fullword ascii
    $s19 = "if(w>=Z.length) {break;}" fullword ascii
    $s20 = "function OYxVeJuJ() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}