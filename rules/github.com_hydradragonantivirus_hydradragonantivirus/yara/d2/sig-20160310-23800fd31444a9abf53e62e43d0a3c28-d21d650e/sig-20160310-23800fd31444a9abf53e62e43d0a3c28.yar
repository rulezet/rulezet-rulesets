rule sig_20160310_23800fd31444a9abf53e62e43d0a3c28 {
  meta:
    description = "datamaliciousorder - file 20160310_23800fd31444a9abf53e62e43d0a3c28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecac7b8d10914d4ce4d6b03f38e609d69877030275f5bbd98dda5d039d83ebf8"

  strings:
    $s1  = "var Uy = true  , rjyo = DaX[7] + DaX[9] + DaX[11];" fullword ascii
    $s2  = "return BTZPSKV[0] + BTZPSKV[2] + BTZPSKV[4] + \".F\" + BTZPSKV[7] + BTZPSKV[9] + BTZPSKV[12] + BTZPSKV[14];" fullword ascii
    $s3  = "wlTvT.open(AfRPJ,YvXnA,false);" fullword ascii
    $s4  = "var BTZPSKV = \"Sc SyMXIQh r uQUyuVonj ipting inBuqXv bGH ile mzXBCMxYwmWraM System pP nTvbd Obj nygFhs ect HgFdvdc\".split(\" " ascii
    $s5  = "var DaX = (\"2.XMLHTTP gRkmbJt FColm XML ream St BGhHQZTh AD zPUMBAh O ojNk D\").split(\" \");" fullword ascii
    $s6  = "if(e>=Z.length) {break;}" fullword ascii
    $s7  = "return new ActiveXObject(rFRzOX);" fullword ascii
    $s8  = "return BdWe.responseBody;" fullword ascii
    $s9  = "function whHtuxl(DHnP,JkGpc) {" fullword ascii
    $s10 = "function hIZRIRx(BdWe) {" fullword ascii
    $s11 = "if (p >= GUHQY.length) {break;}" fullword ascii
    $s12 = "function wBXq(vDfYR) {" fullword ascii
    $s13 = "if (LcNrQ == 933-733){return true;} else {return false;}" fullword ascii
    $s14 = "function KPuUmZzUw(aFwcQ,qQxRd,UvRzc,vDwi) {" fullword ascii
    $s15 = "return XWlfmWV" fullword ascii
    $s16 = "function Tspf(EuVVO,qxYNt) {" fullword ascii
    $s17 = "function PTOGgTkj(KwSIM,kwuLqv) {" fullword ascii
    $s18 = "function vttpwPnrQ(qvvhyaikzZm) {" fullword ascii
    $s19 = "return whHtuxl(Ud,EivDp[234-228]+EivDp[976-969]+EivDp[201-193]);" fullword ascii
    $s20 = "function kgMv(ZMWKP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}