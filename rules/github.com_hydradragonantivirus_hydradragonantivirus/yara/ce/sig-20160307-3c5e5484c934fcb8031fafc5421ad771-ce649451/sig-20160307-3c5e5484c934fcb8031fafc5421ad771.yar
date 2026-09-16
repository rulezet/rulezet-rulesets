rule sig_20160307_3c5e5484c934fcb8031fafc5421ad771 {
  meta:
    description = "datamaliciousorder - file 20160307_3c5e5484c934fcb8031fafc5421ad771.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0a28ccaccc78a2fc770f5ccb85c3b084fd22588324966e8fcc4e69e90454aae"

  strings:
    $s1  = "return LLoGQjS[0] + LLoGQjS[2] + LLoGQjS[4] + \".F\" + LLoGQjS[7] + LLoGQjS[9] + LLoGQjS[12] + LLoGQjS[14];" fullword ascii
    $s2  = "var LLoGQjS = \"Sc YUUawWq r FYXJUxDnJ ipting umJhxLk Mgy ile llNcBEUgepxaPG System iy jlRtu Obj TpvpAn ect isDIOTE\".split(\" " ascii
    $s3  = "var xA = true  , IeiF = iRg[7] + iRg[9] + iRg[11];" fullword ascii
    $s4  = "JLnTo.open(GoHgN,MGSiK,false);" fullword ascii
    $s5  = "var iRg = (\"2.XMLHTTP iFYlBsl GQpoE XML ream St TVteGvbi AD iuDFVQO O TSXN D\").split(\" \");" fullword ascii
    $s6  = "function oUwDBaLQf(noHbQlcBBUd) {" fullword ascii
    $s7  = "function lPqB(IiOGk) {" fullword ascii
    $s8  = "function NTfv(JoFTg,ptGtw) {" fullword ascii
    $s9  = "function IYCIoryL() {" fullword ascii
    $s10 = "function ZQJb(HHtRm) {" fullword ascii
    $s11 = "function vBStEGZsI(ssOJF,jmIsO,xPtgO,DcsT) {" fullword ascii
    $s12 = "if (((new Date())>0,7398189888)) {" fullword ascii
    $s13 = "return new ActiveXObject(bJLykO);" fullword ascii
    $s14 = "function FYDL(PsFMX) {" fullword ascii
    $s15 = "if (t >= IiOGk.length) {break;}" fullword ascii
    $s16 = "function Pfclsmng(HML) {" fullword ascii
    $s17 = "if (PsFMX > 197654-495){return true;} else {return false;}" fullword ascii
    $s18 = "function ioYK(VmtlR) {" fullword ascii
    $s19 = "return MirtxEd" fullword ascii
    $s20 = "if (swxyt == 482-282){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}