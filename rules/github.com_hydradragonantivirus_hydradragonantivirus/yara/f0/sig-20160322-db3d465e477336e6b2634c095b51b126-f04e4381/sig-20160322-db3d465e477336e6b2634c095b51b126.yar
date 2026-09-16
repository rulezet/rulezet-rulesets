rule sig_20160322_db3d465e477336e6b2634c095b51b126 {
  meta:
    description = "datamaliciousorder - file 20160322_db3d465e477336e6b2634c095b51b126.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8052003eddb4485b6fa9c4cc878a62db40911e14521f9d721437c0cf97151eff"

  strings:
    $s1  = "return WScript.CreateObject(HmEvS);" fullword ascii
    $s2  = "var PR = true  , fStV = rTY[7] + rTY[9] + rTY[11];" fullword ascii
    $s3  = "return VMfIKJl[0] + VMfIKJl[2] + VMfIKJl[4] + \".F\" + VMfIKJl[7] + VMfIKJl[9] + VMfIKJl[12] + VMfIKJl[14];" fullword ascii
    $s4  = "XAGm.open(hjrmh,LIIKL,false);" fullword ascii
    $s5  = "var VMfIKJl = MhROZ(mMYiiiqCEB+\" \"+\"System bn inzkB Obj CLpBGC ect bBEqNGK kZawo\", \" \");" fullword ascii
    $s6  = "var rTY = (\"2.XMLHTTP oiWBbpD UbcYe XML ream St kKBLJjcj AD oKsfFGy O LCWG D\").split(\" \");" fullword ascii
    $s7  = "return lufU.ExpandEnvironmentStrings(yzfIS);" fullword ascii
    $s8  = "function gyiP(rgMNv,cKuOR) {" fullword ascii
    $s9  = "return mlrze.status;" fullword ascii
    $s10 = "function oSvu(rZvZz,LIIKL,hjrmh) {" fullword ascii
    $s11 = "function tone(tEWsB) {" fullword ascii
    $s12 = "oSvu(kl,zZvPK+O[Z]+Y, BgF[12]+BgF[14]+BgF[16]); tone(kl); " fullword ascii
    $s13 = "function IkTAuBJb(OxuU) {" fullword ascii
    $s14 = "function MhROZ(fsX,paBTc) {" fullword ascii
    $s15 = "if (KXlcd > 171673-940){return true;} else {return false;}" fullword ascii
    $s16 = "function UsXF(HmEvS) {" fullword ascii
    $s17 = "return vjiVGbo(aX,DTyrJ[477-471]+DTyrJ[677-670]+DTyrJ[613-605]);" fullword ascii
    $s18 = "return fsX.split(paBTc);" fullword ascii
    $s19 = "function ZkxA(lPnhN,qecXy) {" fullword ascii
    $s20 = "if (vmugC == 675-475){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}