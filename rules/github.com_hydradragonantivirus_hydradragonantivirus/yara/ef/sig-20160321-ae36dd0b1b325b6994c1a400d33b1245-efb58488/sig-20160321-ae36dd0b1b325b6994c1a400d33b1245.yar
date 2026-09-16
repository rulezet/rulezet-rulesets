rule sig_20160321_ae36dd0b1b325b6994c1a400d33b1245 {
  meta:
    description = "datamaliciousorder - file 20160321_ae36dd0b1b325b6994c1a400d33b1245.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e407a73fc45425b407405dd0eea7f5f16c0134c062443ac7b04de1b2b482eacc"

  strings:
    $s1  = "return WScript.CreateObject(SIAlC);" fullword ascii
    $s2  = "var fq = true  , aHZB = mcb[7] + mcb[9] + mcb[11];" fullword ascii
    $s3  = "return PoXVYQe[0] + PoXVYQe[2] + PoXVYQe[4] + \".F\" + PoXVYQe[7] + PoXVYQe[9] + PoXVYQe[12] + PoXVYQe[14];" fullword ascii
    $s4  = "var PoXVYQe = tieCT(cOBpytGYXz+\" \"+\"System cq jEMxe Obj EJXNdS ect eMBbAeN wZlvU\", \" \");" fullword ascii
    $s5  = "var mcb = (\"2.XMLHTTP xwoJoOx etVyH XML ream St mLbNBSCo AD WwbdLiP O PmsF D\").split(\" \");" fullword ascii
    $s6  = "function pgLiwJK(QbNW,HmwYk) {" fullword ascii
    $s7  = "return fVndis.position=716-716;" fullword ascii
    $s8  = "function Ksbk(iAJrJ,JiPRc) {" fullword ascii
    $s9  = "return UBtDc.status;" fullword ascii
    $s10 = "function HAOyWdtbC(voCQugrYyEn) {" fullword ascii
    $s11 = "if(N>=f.length) {break;}" fullword ascii
    $s12 = "function juAKT(lAiLVb) {" fullword ascii
    $s13 = "function KFIgQcrf(uOlz) {" fullword ascii
    $s14 = "function RVVm(SIAlC) {" fullword ascii
    $s15 = "return NFH.size;" fullword ascii
    $s16 = "function HVSk(UBtDc) {" fullword ascii
    $s17 = "return QbNW.ExpandEnvironmentStrings(HmwYk);" fullword ascii
    $s18 = "function ZJhh(CVqje) {" fullword ascii
    $s19 = "function ZcDeLCtOY(vRKOH) {" fullword ascii
    $s20 = "function dGci(nBMkO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}