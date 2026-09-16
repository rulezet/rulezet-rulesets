rule sig_20160411_849dc841496cf4ba9e8c204595aebf42 {
  meta:
    description = "datamaliciousorder - file 20160411_849dc841496cf4ba9e8c204595aebf42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01df20f04225c40381981fca6d6d0e42dace46af478daefed0c79efa7b256e88"

  strings:
    $s1  = "return MTMUMZv[0] + MTMUMZv[2] + MTMUMZv[4] + \".F\" + MTMUMZv[7] + MTMUMZv[9] + MTMUMZv[12] + MTMUMZv[14];" fullword ascii
    $s2  = "var IHW = (\"2.XMLHTTP gerVJTt pTzju XML ream St LTlrsxEC AD jytwpgm O ZyEN D\").split(\" \");" fullword ascii
    $s3  = "return \"VecfSoTcxJtxBK\";" fullword ascii
    $s4  = "function evCM(srZIm) {" fullword ascii
    $s5  = "return STm.size;" fullword ascii
    $s6  = "function XeGnHRjnw(IGMWK) {" fullword ascii
    $s7  = "function sirWHT(Kmmf,zfhfwb) {" fullword ascii
    $s8  = "function nUJXOh(ddzivQD) {" fullword ascii
    $s9  = "if (PQact > 183606-620){return true;} else {return false;}" fullword ascii
    $s10 = "function MDglFVO(HDic,LqwwC) {" fullword ascii
    $s11 = "function eCHru(PtteDO) {" fullword ascii
    $s12 = "function oOCSYskC(xURB) {" fullword ascii
    $s13 = "function GWAr(HAAec) {" fullword ascii
    $s14 = "return PtteDO[yZqW[990-990]]=621-621;" fullword ascii
    $s15 = "function exohNcQP(STm) {" fullword ascii
    $s16 = "function ncsk(PQact) {" fullword ascii
    $s17 = "function KWngG(nbVFsorh,hHYP) {" fullword ascii
    $s18 = "if(Z>=V.length) {break;}" fullword ascii
    $s19 = "return SlSal.status;" fullword ascii
    $s20 = "return GYg[bIJp[0]](YmfAS);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}