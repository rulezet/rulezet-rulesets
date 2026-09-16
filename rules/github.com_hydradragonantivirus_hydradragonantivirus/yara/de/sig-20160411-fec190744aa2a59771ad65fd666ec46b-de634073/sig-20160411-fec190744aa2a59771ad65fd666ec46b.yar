rule sig_20160411_fec190744aa2a59771ad65fd666ec46b {
  meta:
    description = "datamaliciousorder - file 20160411_fec190744aa2a59771ad65fd666ec46b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cefbc0566e2854ecac44eff621fd465a2f99097f2ecac2f1aa382922d62eccd"

  strings:
    $s1  = "return GJUMsNl[0] + GJUMsNl[2] + GJUMsNl[4] + \".F\" + GJUMsNl[7] + GJUMsNl[9] + GJUMsNl[12] + GJUMsNl[14];" fullword ascii
    $s2  = "var hM = true  , aHgJ = AkP[7] + AkP[9] + AkP[11];" fullword ascii
    $s3  = "var AkP = (\"2.XMLHTTP QFfUGvU qyWeX XML ream St SyHAbETK AD KjpbGJW O HlLR D\").split(\" \");" fullword ascii
    $s4  = "nHBH.open(nDQKf,YAbHV,false);" fullword ascii
    $s5  = "function jNFM(IhIDN) {" fullword ascii
    $s6  = "return zpA.size;" fullword ascii
    $s7  = "function rOLdjOip(zpA) {" fullword ascii
    $s8  = "function fAiB(WeBct) {" fullword ascii
    $s9  = "function ubuiRFy(hdEs,kFaed) {" fullword ascii
    $s10 = "function pxXK(JFQPY,NiqYm) {" fullword ascii
    $s11 = "DRy = v; break; " fullword ascii
    $s12 = "if (P >= Hfnzw.length) {break;}" fullword ascii
    $s13 = "function voGB(kcCsi) {" fullword ascii
    $s14 = "function hQRszpZRo(EGuFdSdePHw) {" fullword ascii
    $s15 = "return ubuiRFy(Qt,mPyQcY+ghtWM[726-718]);" fullword ascii
    $s16 = "if(v>=o.length) {break;}" fullword ascii
    $s17 = "function Owpbe(LjgtrS) {" fullword ascii
    $s18 = "function IqYqr(aJfshjnh,YdtR) {" fullword ascii
    $s19 = "return \"djLvkkvFPKLkpN\";" fullword ascii
    $s20 = "function omvIoL(dICz,rbbNds) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}