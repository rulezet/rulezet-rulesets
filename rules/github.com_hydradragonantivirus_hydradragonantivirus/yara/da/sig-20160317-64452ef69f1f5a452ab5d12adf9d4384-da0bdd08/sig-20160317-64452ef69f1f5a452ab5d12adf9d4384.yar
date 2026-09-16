rule sig_20160317_64452ef69f1f5a452ab5d12adf9d4384 {
  meta:
    description = "datamaliciousorder - file 20160317_64452ef69f1f5a452ab5d12adf9d4384.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ab215c2a3a9295a6cbc0743c7b2d4c04927bed3228fdc7a15d7cb7754de0ea0"

  strings:
    $s1 = "var kxFGI = \"\\x6e\\x21\";var c0 = \"ai\";var kqZY = \"\\x61g\";var rzT = \"6pu \".charAt(3);var dMwV = \" try\";var oVVvA = \"" ascii
    $s2 = "}}if (Ncm){OrmM = M[(tv) + (S) + (HwyxD) + (vQWw) + (AF0) + (wKmcM) + (KsP) + (z) + (OuIBW)]((db) + (xs)) + (Z) + (jP) + (VQ) + " ascii
    $s3 = "hE);}else{WScript.Echo((gNx) + (d) + (oVVvA) + (dMwV) + (rzT) + (kqZY) + (c0) + (kxFGI));}" fullword ascii
    $s4 = "return VQzZ - FUqNS;}var Ncm = false;for (var EWmQY = 0; EWmQY < AF() * 1; EWmQY++){" fullword ascii
    $s5 = " (qahl) + (zj) + (WcsR) + (OJeso);};function AsFof(){return (ViaH) + (GvWXe) + (hDUo) + (QpBMz);};function AF(){return 22;};func" ascii
    $s6 = ") + (PTD) + (uDAN) + (ELYgF) + (g) + (GqT) + (RUAdR) + (xKwKZ));function citfA(aztAM){M[(Ic)](aztAM, 0, 0);};function W(){return" ascii
    $s7 = "(bHFc) + (iEa) + (jJ) + (YgJ) + (P0) + (cIA) + (M0), false);YvdfD[(PJtac)]();while (YvdfD[(Rn) + (AQg) + (WAUe) + (Iz) + (DOZLU)" ascii
    $s8 = "var RE = new this[(yLnx)]();" fullword ascii
    $s9 = "Ncm = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}