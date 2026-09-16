rule sig_20160317_e91fcc0fcae48055c3ebf1d5274cd857 {
  meta:
    description = "datamaliciousorder - file 20160317_e91fcc0fcae48055c3ebf1d5274cd857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efa2c23d0ca01eedc321274256d9598472085cacead0df0175029d65bdfa5a28"

  strings:
    $s1  = "var ENzLU = \"!\";var QpI = \"ag\\x61\\x69\\x6e\";var P = \"t\\x72y \";var jl = \"ase, \";var xdL = \"\\x50le\";var y = \"6\\x38" ascii
    $s2  = "}}if (yrloH){sa = cjxvC[(WPmMQ) + (p) + (l) + (eMBLi) + (c) + (a) + (HcsxB) + (Xk) + (U) + (PBVs)]((QiOD) + (ec) + (vqi)) + (RrQ" ascii
    $s3  = "return QCOgG - AWz;}var yrloH = false;for (var SGM = 0; SGM < xUP() * 1; SGM++){" fullword ascii
    $s4  = "nction UeS(){return (W) + (aPiBA) + (u) + (A) + (lL) + (LT);};function i(){return (CedfI) + (oo) + (ITjL) + (wc) + (hn);};functi" ascii
    $s5  = "VG) + (KJI) + (xE) + (TolEo) + (gFc) + (bG) + yrloH ? (Yf) + (vgo) + (vz) + (BaTZr) + (gcvZG) + (bWU) : (hmuZZ) + (y);}else{WScr" ascii
    $s6  = "jr) + (T), (Tvqf) + (T0) + (WelO) + (PN) + (HZ) + (tlRUy) + (eOCCy) + (w) + (REaS), false);gPabI[(lNP)]();while (gPabI[(WL) + (s" ascii
    $s7  = "var noB = new this[(DJv) + (gaKDO)]();" fullword ascii
    $s8  = "pt[(CedfI) + (oo) + (ITjL) + (wc) + (hn)]((IElKA) + (N) + (oeY) + (DXMS) + (waXe));function TQ(sCEG){cjxvC[(J)](sCEG, 0, 0);};fu" ascii
    $s9  = "on xUP(){return 22;};function ejT(){" fullword ascii
    $s10 = "yrloH = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}