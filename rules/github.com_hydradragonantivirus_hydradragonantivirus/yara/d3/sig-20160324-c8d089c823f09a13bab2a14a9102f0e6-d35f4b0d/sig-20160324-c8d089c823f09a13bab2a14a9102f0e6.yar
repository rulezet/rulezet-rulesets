rule sig_20160324_c8d089c823f09a13bab2a14a9102f0e6 {
  meta:
    description = "datamaliciousorder - file 20160324_c8d089c823f09a13bab2a14a9102f0e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42522f0ba9eedd5493f90a446e565d5b10d5ac0d6d7642f97f66fb9a023a787e"

  strings:
    $s1  = "return WScript.CreateObject(RDpAC);" fullword ascii
    $s2  = "var iT = true  , eoaZ = pAH[7] + pAH[9] + pAH[11];" fullword ascii
    $s3  = "return xiYAfmN[0] + xiYAfmN[2] + xiYAfmN[4] + \".F\" + xiYAfmN[7] + xiYAfmN[9] + xiYAfmN[12] + xiYAfmN[14];" fullword ascii
    $s4  = "var xiYAfmN = tbKIO(TGlShQpDyH+\" \"+\"System WG sUiJG Obj FRpVSI ect ccsKOEh PLAgF\", \" \");" fullword ascii
    $s5  = "ILuM.open(uAtue,hAqzB,false);" fullword ascii
    $s6  = "var pAH = (\"2.XMLHTTP VVAYaUj YzsWa XML ream St IqjGeqzv AD DreDxiH O IKnZ D\").split(\" \");" fullword ascii
    $s7  = "function xavHf(wygUes) {" fullword ascii
    $s8  = "return Ttffy;" fullword ascii
    $s9  = "function ofQD(RDpAC) {" fullword ascii
    $s10 = "function LmEH(kDqAg) {" fullword ascii
    $s11 = "function Edjh(ScufC) {" fullword ascii
    $s12 = "function tmjUqyRs(mbFX) {" fullword ascii
    $s13 = "function zdrl(cfSMC,TBkjb) {" fullword ascii
    $s14 = "var DYsqWTt = \"hEWSKh*lrJ*pt.S\"+\"hell*OKQINvJ*Scri*\";" fullword ascii
    $s15 = "function vynq(zKGiw,hAqzB,uAtue) {" fullword ascii
    $s16 = "function hndNUCW(MqJw) {" fullword ascii
    $s17 = "return nlygoe/*JU9dO6WNceLOoN252loZNh3wL*/.position=342-342;" fullword ascii
    $s18 = "function SZKE(FXMoD) {" fullword ascii
    $s19 = "return ePO.split(ivFjR);" fullword ascii
    $s20 = "function rnFR(hyqKe,baPuV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}