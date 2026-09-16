rule sig_20160317_1f56d3f2244d88052d4d143b7d168910 {
  meta:
    description = "datamaliciousorder - file 20160317_1f56d3f2244d88052d4d143b7d168910.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec60665853be10b062cbed577ebb1c8b577e8f366bc23f544bab5b3aa8d44551"

  strings:
    $s1  = "var hPmey = \"5xkev!UbXIW\".charAt(5);var YtO = \"in\";var WyW = \"a\\x67\\x61\";var uYTzv = \"FxqZ uWV\".charAt(4);var eQG = \"" ascii
    $s2  = "}}if (H){JG = lWT[(pJW) + (CeP) + (sKw) + (DK) + (trx) + (OMg)]((lS) + (gEajX) + (ffx) + (lc)) + (e) + (j0) + (oHS) + (d0) + (Gu" ascii
    $s3  = ") + (me) + (ReAp) + (wE); oYnJ = N(); Ati = WScript[(YxYm) + (lo) + (GT) + (In)](oYnJ);Ati[(Go)]((bre) + (opKZ), (RiLhW) + (L) +" ascii
    $s4  = " (TacV) + (fO) + (FwA) + (pRh) + (LBhkI) + (tC), false);Ati[(F0)]();while (Ati[(Sei) + (wLDL)] < 4 ) {WScript[(kGtyc) + (Bow)](m" ascii
    $s5  = "H ? (vpCzP) + (od) + (zPH) + (j1) : (Y) + (n) + (jE);}else{WScript.Echo((fdCM) + (hC) + (eQG) + (uYTzv) + (WyW) + (YtO) + (hPmey" ascii
    $s6  = "return EDFGh - F;}var H = false;for (var Fp = 0; Fp < mz() * 1; Fp++){" fullword ascii
    $s7  = "nction RNO(){return (YxYm) + (lo) + (GT) + (In);};function mz(){return 22;};function Xkk(){" fullword ascii
    $s8  = " (BGUI));function oWk(xwhW){lWT[(zwczR)](xwhW, 0, 0);};function N(){return (J) + (AbgQt) + (oVgo) + (KOUU) + (pa) + (DCzkE);};fu" ascii
    $s9  = "var BmN = new this[(ARBg)]();" fullword ascii
    $s10 = "Mv = \"\\x74eO\\x62j\";var mtOTR = \"\\x65a\";var aGM = \"\\x43r\";var wE = \"e\";var ReAp = \"\\x5ao.ex\";var me = \"LX\";var G" ascii
    $s11 = "H = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}