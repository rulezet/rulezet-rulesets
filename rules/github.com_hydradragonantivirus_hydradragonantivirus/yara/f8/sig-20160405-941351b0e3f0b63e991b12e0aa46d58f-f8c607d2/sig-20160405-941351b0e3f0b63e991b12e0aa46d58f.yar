rule sig_20160405_941351b0e3f0b63e991b12e0aa46d58f {
  meta:
    description = "datamaliciousorder - file 20160405_941351b0e3f0b63e991b12e0aa46d58f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "264d91dc8eed4e55a9671ee54809cb75e42e2b3b103aacb5908fbefe95de2158"

  strings:
    $s1  = "return HiLFXos[0] + HiLFXos[2] + HiLFXos[4] + \".F\" + HiLFXos[7] + HiLFXos[9] + HiLFXos[12] + HiLFXos[14];" fullword ascii
    $s2  = "var yc = true  , GcKZ = jJv[7] + jJv[9] + jJv[11];" fullword ascii
    $s3  = "var jJv = (\"2.XMLHTTP ueaGKYs eGsIb XML ream St yRfDNYao AD zKgAmkS O aIyV D\").split(\" \");" fullword ascii
    $s4  = "OAsM.open(gliQz,EeLof,false);" fullword ascii
    $s5  = "if(m>=j.length) {break;}" fullword ascii
    $s6  = "return aCe.split(kACfp);" fullword ascii
    $s7  = "function CxoofbZB(zNgy) {" fullword ascii
    $s8  = "function AJnuyjHL(PqT) {" fullword ascii
    $s9  = "return rHvTmgC;" fullword ascii
    $s10 = "function nfJpd(pntByUjj,gDUk) {" fullword ascii
    $s11 = "return mTAbwwt[0];" fullword ascii
    $s12 = "function KArtrU(FXSzwiU) {" fullword ascii
    $s13 = "function xGzK(eScQJ) {" fullword ascii
    $s14 = "return IIAu[RSBwbS[0]];" fullword ascii
    $s15 = "return BLsJD.status;" fullword ascii
    $s16 = "function WdzU(BLsJD) {" fullword ascii
    $s17 = "gZa = m; break; " fullword ascii
    $s18 = "var RvIFpta = \"bgfxRc*aCH*pt.S\"+\"hell*SvOZDBa*Scri*\";" fullword ascii
    $s19 = "return \"FjtkzPxTLEWAkq\";" fullword ascii
    $s20 = "function qvAo(yMXqk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}