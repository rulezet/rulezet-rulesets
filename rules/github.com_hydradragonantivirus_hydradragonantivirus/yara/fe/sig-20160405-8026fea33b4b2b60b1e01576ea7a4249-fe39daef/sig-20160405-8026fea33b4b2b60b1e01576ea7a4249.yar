rule sig_20160405_8026fea33b4b2b60b1e01576ea7a4249 {
  meta:
    description = "datamaliciousorder - file 20160405_8026fea33b4b2b60b1e01576ea7a4249.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d11c93eeaa041350bcb207cb1b605393ef16f8c6704c4226b227cb8ac8da9b1"

  strings:
    $s1  = "return LSnPgcF[0] + LSnPgcF[2] + LSnPgcF[4] + \".F\" + LSnPgcF[7] + LSnPgcF[9] + LSnPgcF[12] + LSnPgcF[14];" fullword ascii
    $s2  = "var Kl = true  , oWel = BRK[7] + BRK[9] + BRK[11];" fullword ascii
    $s3  = "NukC.open(mToYm,XXFno,false);" fullword ascii
    $s4  = "var BRK = (\"2.XMLHTTP jdGHfKT tFQIA XML ream St ECyBHQqL AD kHinhWE O lmUT D\").split(\" \");" fullword ascii
    $s5  = "function oAiX(JJcDD,OxAHV) {" fullword ascii
    $s6  = "function gZUG(Hbdlb,XXFno,mToYm) {" fullword ascii
    $s7  = "function bVjX(pLDYt) {" fullword ascii
    $s8  = "function NnXx(rBeFZ) {" fullword ascii
    $s9  = "return jxpjz.status;" fullword ascii
    $s10 = "function vlpnz(iDYJSE) {" fullword ascii
    $s11 = "return RdIm[pPQIvY[0]];" fullword ascii
    $s12 = "TMoNJn(wYU,budA);" fullword ascii
    $s13 = "function FhbQE(eexdSVeo,Mtzg) {" fullword ascii
    $s14 = "return vIvL;" fullword ascii
    $s15 = "function TMoNJn(IoYG,CoTBtN) {" fullword ascii
    $s16 = "function BAGI(gefYm,BUgMD) {" fullword ascii
    $s17 = "if (OApyD > 151809-578){return true;} else {return false;}" fullword ascii
    $s18 = "function VRuVEK(PnZZHxV) {" fullword ascii
    $s19 = "return WfT.size;" fullword ascii
    $s20 = "return \"KSgDIuVlScvIfU\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}