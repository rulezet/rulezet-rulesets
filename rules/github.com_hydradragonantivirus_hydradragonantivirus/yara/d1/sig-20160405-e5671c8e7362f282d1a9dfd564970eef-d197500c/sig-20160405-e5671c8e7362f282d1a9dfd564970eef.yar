rule sig_20160405_e5671c8e7362f282d1a9dfd564970eef {
  meta:
    description = "datamaliciousorder - file 20160405_e5671c8e7362f282d1a9dfd564970eef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50321e76c5c937da990e1a2ee465f36c8fce2716d50463a20dbcb7f5447b83bc"

  strings:
    $s1  = "return UFGqTaK[0] + UFGqTaK[2] + UFGqTaK[4] + \".F\" + UFGqTaK[7] + UFGqTaK[9] + UFGqTaK[12] + UFGqTaK[14];" fullword ascii
    $s2  = "var nO = true  , ifxS = tsP[7] + tsP[9] + tsP[11];" fullword ascii
    $s3  = "ynlr.open(uEDDF,yYPMg,false);" fullword ascii
    $s4  = "var tsP = (\"2.XMLHTTP VUUFcme abIQh XML ream St KmWNBXza AD AWsxtti O uCpM D\").split(\" \");" fullword ascii
    $s5  = "if (WNvno == 392-192){return true;} else {return false;}" fullword ascii
    $s6  = "function aGvC(Lwizq) {" fullword ascii
    $s7  = "function JFSEMgod(iuV) {" fullword ascii
    $s8  = "GZT = i; break; " fullword ascii
    $s9  = "function JMzBc(SdHNcn) {" fullword ascii
    $s10 = "function WZXM(TbZRW) {" fullword ascii
    $s11 = "return FITX[KSPhPU[0]];" fullword ascii
    $s12 = "function Bnra(mCbNP,mSMPl) {" fullword ascii
    $s13 = "function yxHDePgzH(beISC) {" fullword ascii
    $s14 = "return \"pqpMmVXAjGNQph\";" fullword ascii
    $s15 = "if (MEvDz > 179859-213){return true;} else {return false;}" fullword ascii
    $s16 = "function IGoiZH(XEkC,ARhYRY) {" fullword ascii
    $s17 = "if (D >= mJyEY.length) {break;}" fullword ascii
    $s18 = "var NjMMVLp = \"eyCsWx*SjK*pt.S\"+\"hell*PSFgeHV*Scri*\";" fullword ascii
    $s19 = "function eyxfJht(MmhV,UFdqV) {" fullword ascii
    $s20 = "function JWMHdA(kcEcRfD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}