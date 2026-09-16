rule sig_20160312_b91044a8eb0faf22161fbc653267eff2 {
  meta:
    description = "datamaliciousorder - file 20160312_b91044a8eb0faf22161fbc653267eff2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40b30350fe43b5ec2cf9b7728c66c9bd3ed9c2c92029e1d44db32ed65bb91d8b"

  strings:
    $s1  = "return BlJyHSs[0] + BlJyHSs[2] + BlJyHSs[4] + \".F\" + BlJyHSs[7] + BlJyHSs[9] + BlJyHSs[12] + BlJyHSs[14];" fullword ascii
    $s2  = "var rQ = true  , QLmt = TvO[7] + TvO[9] + TvO[11];" fullword ascii
    $s3  = "var TvO = (\"2.XMLHTTP shVODbV ywENq XML ream St RfDFDyZS AD rMkUQIZ O Wqdd D\").split(\" \");" fullword ascii
    $s4  = "var BlJyHSs = \"Sc xKcXvlS r ezjkTsCYy ipting KzzBtlZ GZA ile rEAFssjdsOSArO System mn GcgAc Obj ffJIKR ect tjrpcTW\".split(\" " ascii
    $s5  = "wHpux.open(SXwjd,PZcyt,false);" fullword ascii
    $s6  = "function GnBR(coMdi,OsiXu) {" fullword ascii
    $s7  = "if (MyhUY == 828-628){return true;} else {return false;}" fullword ascii
    $s8  = "return dDnsMNd" fullword ascii
    $s9  = "function eckE(wHpux,PZcyt,SXwjd) {" fullword ascii
    $s10 = "function gEzW(DUsBi) {" fullword ascii
    $s11 = "function kIhag(cTPzyI) {" fullword ascii
    $s12 = "pdt = z; break; " fullword ascii
    $s13 = "function FYTBfndxE() {" fullword ascii
    $s14 = "function leDm(rEdev) {" fullword ascii
    $s15 = "function dBvCBLf(sPll) {" fullword ascii
    $s16 = "function NrHg(truxe,FFpED) {" fullword ascii
    $s17 = "function qWkJUeYob(JQBpGduvBpq) {" fullword ascii
    $s18 = "return new ActiveXObject(ylkFVn);" fullword ascii
    $s19 = "function KLro(ZMARF) {" fullword ascii
    $s20 = "if(z>=u.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}