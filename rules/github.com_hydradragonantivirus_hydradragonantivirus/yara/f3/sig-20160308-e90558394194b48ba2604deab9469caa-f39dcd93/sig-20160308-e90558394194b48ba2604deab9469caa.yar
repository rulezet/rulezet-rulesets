rule sig_20160308_e90558394194b48ba2604deab9469caa {
  meta:
    description = "datamaliciousorder - file 20160308_e90558394194b48ba2604deab9469caa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "120a5c0d521236f49763f4d39d37770ffb82fbd5022111eca533fe84fc693cec"

  strings:
    $s1  = "var qp = true  , yvrI = uBj[7] + uBj[9] + uBj[11];" fullword ascii
    $s2  = "return JosTFGg[0] + JosTFGg[2] + JosTFGg[4] + \".F\" + JosTFGg[7] + JosTFGg[9] + JosTFGg[12] + JosTFGg[14];" fullword ascii
    $s3  = "var JosTFGg = \"Sc zlCRopR r jwLxjQTUI ipting qnFYytz dYI ile VZFAdCtsMHsSZH System gg sPgnB Obj rcbxjq ect NSQYwOy\".split(\" " ascii
    $s4  = "QkJym.open(WxLAB,FQWVI,false);" fullword ascii
    $s5  = "var uBj = (\"2.XMLHTTP MFmlvGt fhldT XML ream St tHumDZgs AD AUGJuex O WMgj D\").split(\" \");" fullword ascii
    $s6  = "function OQkl(ZrvuN) {" fullword ascii
    $s7  = "function pgYMjnA(XvWA) {" fullword ascii
    $s8  = "if (((new Date())>0,73818888)) {" fullword ascii
    $s9  = "if (I >= kCfkB.length) {break;}" fullword ascii
    $s10 = "if (wjrZY > 169551-184){return true;} else {return false;}" fullword ascii
    $s11 = "function Sqwv(LVUXx) {" fullword ascii
    $s12 = "function coiw(ljHjG) {" fullword ascii
    $s13 = "if(W>=p.length) {break;}" fullword ascii
    $s14 = "return iLZ.size;" fullword ascii
    $s15 = "return new ActiveXObject(wdXQfQ);" fullword ascii
    $s16 = "function oVRL(hYVsi) {" fullword ascii
    $s17 = "function AyWf(wTUgm) {" fullword ascii
    $s18 = "function SmZP(wjrZY) {" fullword ascii
    $s19 = "function tFpfxCcT() {" fullword ascii
    $s20 = "function gVzwH(wdXQfQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}