rule sig_20160317_87b3d09e95baa2a73014859612cef9a6 {
  meta:
    description = "datamaliciousorder - file 20160317_87b3d09e95baa2a73014859612cef9a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b91b9b317e7ef89ef696aa5f66e7eab222f9f1d8b3644a22c82eba7631de3637"

  strings:
    $s1  = "var Ir = \"n!\";var B2 = \"si\".charAt(1);var i = \"\\x79 \\x61g\\x61\";var Wc = \"\\x65\\x2c\\x20\\x74r\";var g = \"Pleas\";var" ascii
    $s2  = "(J) + (T)]();while (hOUI[(mDvn) + (FjCH) + (nQGS)] < 4 ) {WScript[(nbs) + (VC)](uLPaN() * 10)};Z = WScript[P()]((r) + (C) + (WQo" ascii
    $s3  = "+ (oAUP);}else{WScript.Echo((g) + (Wc) + (i) + (B2) + (Ir));}" fullword ascii
    $s4  = "}}if (VJF){gC = PKsYn[(ahM) + (ueMY) + (iCc) + (l) + (k) + (Npkm) + (ju) + (Vuh) + (G)]((krJF) + (m) + (AwZ) + (vKF)) + (H0) + (" ascii
    $s5  = "return B - KGL;}var VJF = false;for (var ASd = 0; ASd < uLPaN() * 1; ASd++){" fullword ascii
    $s6  = "var by = new this[(DJPyb) + (y)]();" fullword ascii
    $s7  = "Ho)]((Zz), (y0) + (hrxD) + (MbAdP) + (yapWp) + (UcQ) + (OqmzE) + (cEQls) + (PND) + (HPy) + (pf) + (YiuS) + (hpAnN), false);hOUI[" ascii
    $s8  = " + (O) + (Brb) + (lE);};function P(){return (x) + (QSd) + (gUkh) + (peqj);};function uLPaN(){return 22;};function uHc(){" fullword ascii
    $s9  = "peqj)]((B0) + (idIAs) + (apUcA) + (PT) + (UpvCb) + (cgkeG));function e(lxoVm){PKsYn[(Z0)](lxoVm, 0, 0);};function R(){return (t)" ascii
    $s10 = "VJF = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}