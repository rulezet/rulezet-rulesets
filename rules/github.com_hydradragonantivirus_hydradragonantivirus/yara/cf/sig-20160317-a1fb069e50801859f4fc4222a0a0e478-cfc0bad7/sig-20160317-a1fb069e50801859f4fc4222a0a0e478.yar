rule sig_20160317_a1fb069e50801859f4fc4222a0a0e478 {
  meta:
    description = "datamaliciousorder - file 20160317_a1fb069e50801859f4fc4222a0a0e478.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19740b3664612568c657ffedd9158536aaff304756528ce1de9679c56be84b86"

  strings:
    $s1  = "var KsncO = \"\\x61i\\x6e\\x21\";var HWgDj = \"g\";var c = \" a\";var NgIYF = \",\\x20try\";var rSUDq = \"ase\";var dq = \"P\\x6" ascii
    $s2  = "uhXp[(YFDB)]();while (auhXp[(ZtNp) + (KgBMD) + (Fw) + (z)] < 4 ) {WScript[(p) + (EJxN)](WW() * 10)};NH = WScript[JgR()]((oatSh) " ascii
    $s3  = "(OW) + r ? (P) + (VYu) : (mPA) + (HZrZ) + (PEOFP) + (vlCt) + (PCXu);}else{WScript.Echo((dq) + (rSUDq) + (NgIYF) + (c) + (HWgDj) " ascii
    $s4  = "}}if (r){gvbOf = wgK[(gzX) + (IvlXV) + (WmlN) + (trbE) + (nN) + (iHo) + (aNYY) + (vbBgo) + (LoOZU) + (aau) + (GTytv)]((GDkN) + (" ascii
    $s5  = "return pDxf - vP;}var r = false;for (var b = 0; b < WW() * 1; b++){" fullword ascii
    $s6  = "T) + (a) + (aIo) + (nL) + (S));function jG(JMG){wgK[(Y)](JMG, 0, 0);};function q(){return (fK) + (Betzi) + (C) + (JVDt) + (G);};" ascii
    $s7  = "hXp[(i) + (L)]((W) + (Eqhz), (OHEX) + (we) + (VKMPD) + (m) + (L0) + (r0) + (Pfz) + (gyDmy) + (kLzKj) + (Nux) + (jUdtc), false);a" ascii
    $s8  = "function JgR(){return (T) + (qNxt) + (gg) + (vUO) + (RXYM) + (bBt);};function WW(){return 22;};function zam(){" fullword ascii
    $s9  = "var oXLTe = new this[(Jj) + (ufH)]();" fullword ascii
    $s10 = "r = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}