rule sig_20160317_9b6f72067e3f5af368247635acacaf90 {
  meta:
    description = "datamaliciousorder - file 20160317_9b6f72067e3f5af368247635acacaf90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c60ab372995044e273d9ab414006ede0ca2a115d378623a6f23994359b747053"

  strings:
    $s1  = "var WwuCz = \"57Tu!Axlc\".charAt(4);var X = \"ai\\x6e\";var iu = \"y a\\x67\";var Gu = \"rH\".charAt(0);var S0 = \"e, t\";var iK" ascii
    $s2  = ");}else{WScript.Echo((B) + (bylc) + (iKLmr) + (S0) + (Gu) + (iu) + (X) + (WwuCz));}" fullword ascii
    $s3  = "}}if (zomz){l = Dz[(L) + (t) + (Tq) + (s0) + (PvU) + (hLVAs) + (o) + (vPFms) + (XZYa) + (iuiOi)]((Wyd) + (WS) + (gYr)) + (WlWsV)" ascii
    $s4  = "return KyXp - UgWun;}var zomz = false;for (var lotK = 0; lotK < P() * 1; lotK++){" fullword ascii
    $s5  = "2ody\";var T0 = \"s\\x65\";var kYv = \"on\";var vaAN = \"Resp\";var JD = \"e\";var k = \"wri\\x74\";var QoaW = \"Jb5e\".charAt(3" ascii
    $s6  = "(YOCB) + (cTjrM) + (glSR) + (rfc));function sX(uUrfg){Dz[(s)](uUrfg, 0, 0);};function oZFzv(){return (T) + (qBOA) + (bDP);};func" ascii
    $s7  = "nr) + (uhL) + (oSCn) + (HToc) + (AF) + (yvl) + (QTB) + (Pmusl) + (AzJy) + (S) + (I) + (D), false);HbDiS[(FIA) + (YclmP)]();while" ascii
    $s8  = "tion ud(){return (kJ) + (jTZ) + (P0);};function P(){return 22;};function xEGY(){" fullword ascii
    $s9  = "jBB) + (pHBL) + (H));Di[((Li) + (Ef))]();Di[(RR) + (RiOt) + (QoaW)] = 1;Di[(k) + (JD)](HbDiS[(vaAN) + (kYv) + (T0) + (TmCZT)]);D" ascii
    $s10 = "var FxN = new this[(iGfok)]();" fullword ascii
    $s11 = "zomz = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}