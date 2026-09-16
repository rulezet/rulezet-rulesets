rule sig_20160322_fcb11c422c1bcf30cffac61de51a1daa {
  meta:
    description = "datamaliciousorder - file 20160322_fcb11c422c1bcf30cffac61de51a1daa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03e09e2f1211290909a13094239df29d64a3b9486c9facfef17f8775f3bf58de"

  strings:
    $s1  = "return WScript.CreateObject(YYzTJ);" fullword ascii
    $s2  = "return WuwZYNM[0] + WuwZYNM[2] + WuwZYNM[4] + \".F\" + WuwZYNM[7] + WuwZYNM[9] + WuwZYNM[12] + WuwZYNM[14];" fullword ascii
    $s3  = "var MZ = true  , lsAT = hBk[7] + hBk[9] + hBk[11];" fullword ascii
    $s4  = "var hBk = (\"2.XMLHTTP qnvVeky RTSol XML ream St saMCsKhG AD RONhBLv O eMCN D\").split(\" \");" fullword ascii
    $s5  = "var WuwZYNM = GGYHB(rAWiFrjmAC+\" \"+\"System jf FsGXm Obj rkBmWh ect dTfMHCs ZAsfX\", \" \");" fullword ascii
    $s6  = "RKff.open(hsJYG,gcPjq,false);" fullword ascii
    $s7  = "if(y>=q.length) {break;}" fullword ascii
    $s8  = "return RVekb.status;" fullword ascii
    $s9  = "function JVlE(qoukv) {" fullword ascii
    $s10 = "return INDc.ExpandEnvironmentStrings(eNlje);" fullword ascii
    $s11 = "function jjHvrSYKI(PzXJvpCdilO) {" fullword ascii
    $s12 = "return SieWIlX(aR,jLMcE[705-699]+jLMcE[840-833]+jLMcE[500-492]);" fullword ascii
    $s13 = "function PaQQ(WLVVN) {" fullword ascii
    $s14 = "return iHNEwQ.position=613-613;" fullword ascii
    $s15 = "function SieWIlX(INDc,eNlje) {" fullword ascii
    $s16 = "function ekuLZXHL(rVss) {" fullword ascii
    $s17 = "return nik.split(fJNJe);" fullword ascii
    $s18 = "function cQhczaSU(ZKs) {" fullword ascii
    $s19 = "function xzms(JMPfz) {" fullword ascii
    $s20 = "function DxYd(RVekb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}