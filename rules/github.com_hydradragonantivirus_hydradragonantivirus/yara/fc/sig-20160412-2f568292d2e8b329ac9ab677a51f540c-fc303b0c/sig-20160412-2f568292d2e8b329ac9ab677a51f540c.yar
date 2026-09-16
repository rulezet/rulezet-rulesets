rule sig_20160412_2f568292d2e8b329ac9ab677a51f540c {
  meta:
    description = "datamaliciousorder - file 20160412_2f568292d2e8b329ac9ab677a51f540c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d165ac74a6691e94e554c4a2e8ef90e1b1165c2240b44028c758633c3896ad9a"

  strings:
    $s1  = "return iXvDOGx[0] + iXvDOGx[2] + iXvDOGx[4] + \".F\" + iXvDOGx[7] + iXvDOGx[9] + iXvDOGx[12] + iXvDOGx[14];" fullword ascii
    $s2  = "var wy = true  , mQfG = eli[7] + eli[9] + eli[11];" fullword ascii
    $s3  = "oMbh.open(PJNkO,BMSMB,false);" fullword ascii
    $s4  = "var eli = (\"2.XMLHTTP lIzfwPM ubETt XML ream St PyNSWGnw AD tnBxnwc O FSrr D\").split(\" \");" fullword ascii
    $s5  = "return \"CotJlcrniMZXoi\";" fullword ascii
    $s6  = "function FEfbF(VnH,ZOvAH) {" fullword ascii
    $s7  = "function ySZw(nDIMU,BMSMB,PJNkO) {" fullword ascii
    $s8  = "function qapF(IzVFX) {" fullword ascii
    $s9  = "function gqXazOrnz(TNZWDxAEqNz) {" fullword ascii
    $s10 = "function dtyIgC(QwSroYY) {" fullword ascii
    $s11 = "function VvXegaebg(QPtSb) {" fullword ascii
    $s12 = "function qzna(gBWax,hgXYA) {" fullword ascii
    $s13 = "function OKhV(YwnWz) {" fullword ascii
    $s14 = "function btzLT(HIbciF) {" fullword ascii
    $s15 = "return VnH[akSp[0]](ZOvAH);" fullword ascii
    $s16 = "if (c >= aChho.length) {break;}" fullword ascii
    $s17 = "function lwkS(UQljq) {" fullword ascii
    $s18 = "function ewytoeHb(nyDj) {" fullword ascii
    $s19 = "if (UQljq > 164596-853){return true;} else {return false;}" fullword ascii
    $s20 = "return gzZu[oGaFapc[0]+oGaFapc[1]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}