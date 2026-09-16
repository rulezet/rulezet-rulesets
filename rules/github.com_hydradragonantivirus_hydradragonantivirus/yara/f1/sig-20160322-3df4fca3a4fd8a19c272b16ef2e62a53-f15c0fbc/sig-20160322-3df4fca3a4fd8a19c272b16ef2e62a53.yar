rule sig_20160322_3df4fca3a4fd8a19c272b16ef2e62a53 {
  meta:
    description = "datamaliciousorder - file 20160322_3df4fca3a4fd8a19c272b16ef2e62a53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91a05260ca9da162674e0a232370be8d74d52d52cb3be63c9d2f5c06d4a7df24"

  strings:
    $s1  = "return WScript.CreateObject(VBgWv);" fullword ascii
    $s2  = "return EltOiVB[0] + EltOiVB[2] + EltOiVB[4] + \".F\" + EltOiVB[7] + EltOiVB[9] + EltOiVB[12] + EltOiVB[14];" fullword ascii
    $s3  = "var Ni = true  , AJzS = oOH[7] + oOH[9] + oOH[11];" fullword ascii
    $s4  = "function EuOe(xaCMd) {" fullword ascii
    $s5  = "cRtD.open(Rbafp,YbndM,false);" fullword ascii
    $s6  = "var oOH = (\"2.XMLHTTP NAWsiIu SYuRE XML ream St NyHILyob AD XXcPaOl O zben D\").split(\" \");" fullword ascii
    $s7  = "var EltOiVB = zyaSw(UoYaxcPsHh+\" \"+\"System Rn VmPLS Obj hISHlh ect AdznBFe DVBXy\", \" \");" fullword ascii
    $s8  = "return yOjLZ;" fullword ascii
    $s9  = "function CCgEi(DwAUGp) {" fullword ascii
    $s10 = "return PVEg.ExpandEnvironmentStrings(BGSyC);" fullword ascii
    $s11 = "if (qXfmu > 198298-557){return true;} else {return false;}" fullword ascii
    $s12 = "function GMZowWh(ZHCr) {" fullword ascii
    $s13 = "function zyaSw(taB,SyLGC) {" fullword ascii
    $s14 = "function LzZS(hXcoq) {" fullword ascii
    $s15 = "function MSzY(WILZf,YbndM,Rbafp) {" fullword ascii
    $s16 = "if (N >= PYNSy.length) {break;}" fullword ascii
    $s17 = "function bUgghGl(PVEg,BGSyC) {" fullword ascii
    $s18 = "function FAUy(VBgWv) {" fullword ascii
    $s19 = "function Bfosc(kpAyHM) {" fullword ascii
    $s20 = "function rLfX(fjVtO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}