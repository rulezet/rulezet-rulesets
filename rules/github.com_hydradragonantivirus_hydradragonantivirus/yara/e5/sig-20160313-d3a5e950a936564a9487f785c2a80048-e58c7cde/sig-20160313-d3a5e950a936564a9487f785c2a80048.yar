rule sig_20160313_d3a5e950a936564a9487f785c2a80048 {
  meta:
    description = "datamaliciousorder - file 20160313_d3a5e950a936564a9487f785c2a80048.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dd058081bf4e99dfe9004f043f8e20a09c5f087e777aa373fc09dad75a5833b"

  strings:
    $s1  = "return cHAsOba[0] + cHAsOba[2] + cHAsOba[4] + \".F\" + cHAsOba[7] + cHAsOba[9] + cHAsOba[12] + cHAsOba[14];" fullword ascii
    $s2  = "var eU = true  , sbpC = rVT[7] + rVT[9] + rVT[11];" fullword ascii
    $s3  = "var cHAsOba = \"Sc PSpEbRq r WWPQymOSm ipting KHYJvnu cov ile VUjjAyzPdAmXzk System Oq vZenS Obj SJNjBp ect evLbLwF\".split(\" " ascii
    $s4  = "kwdXZ.open(IvSgF,nvbTh,false);" fullword ascii
    $s5  = "var rVT = (\"2.XMLHTTP gYWZXkQ cUcna XML ream St aAiGQoeO AD EbcYOot O TOld D\").split(\" \");" fullword ascii
    $s6  = "return new ActiveXObject(BiYiWC);" fullword ascii
    $s7  = "if (RFpME == 953-753){return true;} else {return false;}" fullword ascii
    $s8  = "function YYugNqOaf() {" fullword ascii
    $s9  = "if (j >= AJJmk.length) {break;}" fullword ascii
    $s10 = "function vzVa(RFpME) {" fullword ascii
    $s11 = "function AeXr(pdsNX) {" fullword ascii
    $s12 = "function SbcSO(LULPFo) {" fullword ascii
    $s13 = "function vDCJETI(WeCo,tWrFV) {" fullword ascii
    $s14 = "if (pdsNX > 185169-745){return true;} else {return false;}" fullword ascii
    $s15 = "return LULPFo.position=336-336;" fullword ascii
    $s16 = "return LltiN;" fullword ascii
    $s17 = "function WEKp(AJJmk) {" fullword ascii
    $s18 = "function AppM(wSRua) {" fullword ascii
    $s19 = "return rHu.size;" fullword ascii
    $s20 = "function tNfji(BiYiWC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}