rule sig_20160313_31d372c0a149a034bc210f046ed6e319 {
  meta:
    description = "datamaliciousorder - file 20160313_31d372c0a149a034bc210f046ed6e319.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a755b95a9a6a63f77c8dfb1a2abe1198ce63e300008b15cd27fc43c594e1a78"

  strings:
    $s1  = "var jy = true  , Xvkn = zEH[7] + zEH[9] + zEH[11];" fullword ascii
    $s2  = "return MovBcij[0] + MovBcij[2] + MovBcij[4] + \".F\" + MovBcij[7] + MovBcij[9] + MovBcij[12] + MovBcij[14];" fullword ascii
    $s3  = "var zEH = (\"2.XMLHTTP MZqHqTo MBJJI XML ream St qJLBVLvF AD dOfddMe O jgCu D\").split(\" \");" fullword ascii
    $s4  = "TgDQp.open(xDLVt,cWfZU,false);" fullword ascii
    $s5  = "var MovBcij = \"Sc vlordIi r kKlIZHjoc ipting yxXiJDD XXd ile loUsBtWiLOpLOY System KY yCCLv Obj PFjlMJ ect KNymrqC\".split(\" " ascii
    $s6  = "return jWC.size;" fullword ascii
    $s7  = "function nbTZGwAsy(OypoBkOrckL) {" fullword ascii
    $s8  = "function dFNr(uBuVh,dSZPU) {" fullword ascii
    $s9  = "function xjwEuPL(AYbp,pUPVQ) {" fullword ascii
    $s10 = "function mrRN(FogVo,wqVPz) {" fullword ascii
    $s11 = "function Xoaj(wtfNc) {" fullword ascii
    $s12 = "function qutPimEfq() {" fullword ascii
    $s13 = "return Ecgdxj.position=525-525;" fullword ascii
    $s14 = "return BXPyIxA" fullword ascii
    $s15 = "function KSTXVmw(tLOQ) {" fullword ascii
    $s16 = "function uGoHa(Ecgdxj) {" fullword ascii
    $s17 = "function ZjowQ(YlNEuX) {" fullword ascii
    $s18 = "return pEonx.status;" fullword ascii
    $s19 = "function umyc(jFmkd) {" fullword ascii
    $s20 = "return xjwEuPL(LB,unLUi[607-601]+unLUi[822-815]+unLUi[187-179]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}