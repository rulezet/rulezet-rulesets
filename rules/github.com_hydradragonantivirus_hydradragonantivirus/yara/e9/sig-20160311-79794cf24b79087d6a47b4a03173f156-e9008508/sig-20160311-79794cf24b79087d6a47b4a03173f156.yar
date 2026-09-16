rule sig_20160311_79794cf24b79087d6a47b4a03173f156 {
  meta:
    description = "datamaliciousorder - file 20160311_79794cf24b79087d6a47b4a03173f156.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac0da84cb56c34caa8418075ead4dd1cd791abb210081241a28196e1cb6a839"

  strings:
    $s1  = "return VUZhqsv[0] + VUZhqsv[2] + VUZhqsv[4] + \".F\" + VUZhqsv[7] + VUZhqsv[9] + VUZhqsv[12] + VUZhqsv[14];" fullword ascii
    $s2  = "var vl = true  , OXdY = EnN[7] + EnN[9] + EnN[11];" fullword ascii
    $s3  = "var EnN = (\"2.XMLHTTP snfxoYN kSuFX XML ream St VyFRLjvN AD zIwwMKj O sqtM D\").split(\" \");" fullword ascii
    $s4  = "var VUZhqsv = \"Sc vQxyxFN r zqrLVMkPV ipting UpNLvnt lki ile BfDosEVdcPUPEe System ng Bymnq Obj gDPmrh ect ZsbvyTP\".split(\" " ascii
    $s5  = "scpzH.open(iKFjt,ATUTW,false);" fullword ascii
    $s6  = "return HYY.size;" fullword ascii
    $s7  = "function TmkZIGPQD(UGnMqzSZDpi) {" fullword ascii
    $s8  = "function GmUGdTsc(HYY) {" fullword ascii
    $s9  = "function sHPd(hHmWK,xateY) {" fullword ascii
    $s10 = "function dQEl(aPPzj) {" fullword ascii
    $s11 = "function jspg(fdlMk) {" fullword ascii
    $s12 = "function fmhxhQq(ANWO,AqhED) {" fullword ascii
    $s13 = "function WmmiUWGqJ() {" fullword ascii
    $s14 = "return NbFnUbs" fullword ascii
    $s15 = "if(W>=x.length) {break;}" fullword ascii
    $s16 = "function CMGIPdD(SRme) {" fullword ascii
    $s17 = "return new ActiveXObject(lwFgNT);" fullword ascii
    $s18 = "function BUZi(RYeIz) {" fullword ascii
    $s19 = "if (iPQlB > 138715-340){return true;} else {return false;}" fullword ascii
    $s20 = "return fmhxhQq(Ds,MOkRU[369-363]+MOkRU[336-329]+MOkRU[343-335]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}