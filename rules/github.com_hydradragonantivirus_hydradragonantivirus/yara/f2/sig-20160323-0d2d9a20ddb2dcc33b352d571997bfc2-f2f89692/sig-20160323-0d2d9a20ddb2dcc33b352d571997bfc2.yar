rule sig_20160323_0d2d9a20ddb2dcc33b352d571997bfc2 {
  meta:
    description = "datamaliciousorder - file 20160323_0d2d9a20ddb2dcc33b352d571997bfc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39b876dca6bec5872066d150d88835ba33c5d1180c7dd7b565d40119068d9128"

  strings:
    $s1  = "return WScript.CreateObject(IFirQ);" fullword ascii
    $s2  = "var dq = true  , OJQj = GIa[7] + GIa[9] + GIa[11];" fullword ascii
    $s3  = "return VBeBlvF[0] + VBeBlvF[2] + VBeBlvF[4] + \".F\" + VBeBlvF[7] + VBeBlvF[9] + VBeBlvF[12] + VBeBlvF[14];" fullword ascii
    $s4  = "var GIa = (\"2.XMLHTTP pNltuXI ZqYku XML ream St hkOAnGKs AD jqzJCDk O UCHS D\").split(\" \");" fullword ascii
    $s5  = "var VBeBlvF = pfQoC(gjddpfdNXb+\" \"+\"System nI btVIB Obj eheGXz ect cZvLMjI ZPuLw\", \" \");" fullword ascii
    $s6  = "tcJR.open(NgRmc,jXydI,false);" fullword ascii
    $s7  = "function uwkVYhBn(YcR) {" fullword ascii
    $s8  = "function ohuyr(qvwJAF) {" fullword ascii
    $s9  = "function rzOI(vPCpA) {" fullword ascii
    $s10 = "return azU.split(qAJLW);" fullword ascii
    $s11 = "return XvMy[aYFOtT[0]];" fullword ascii
    $s12 = "function pmua(wooyl) {" fullword ascii
    $s13 = "function uBIufXU(XvMy) {" fullword ascii
    $s14 = "if(v>=D.length) {break;}" fullword ascii
    $s15 = "function eyXIChhC(kPcJ) {" fullword ascii
    $s16 = "PFh = v; break; " fullword ascii
    $s17 = "function Pden(IFirQ) {" fullword ascii
    $s18 = "return new ActiveXObject(rlGQ);" fullword ascii
    $s19 = "function iYjvuTwxQ(OjhXgvaTHNb) {" fullword ascii
    $s20 = "function TNfRt(VzxkNe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}