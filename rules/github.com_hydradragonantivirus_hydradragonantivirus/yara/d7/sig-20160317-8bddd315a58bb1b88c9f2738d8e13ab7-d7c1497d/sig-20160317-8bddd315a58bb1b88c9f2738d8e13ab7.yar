rule sig_20160317_8bddd315a58bb1b88c9f2738d8e13ab7 {
  meta:
    description = "datamaliciousorder - file 20160317_8bddd315a58bb1b88c9f2738d8e13ab7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "393dbc8ca317d856a8e096c3ffb3067580bfc2186e1d0388d3ea4e1216f79885"

  strings:
    $s1  = "var pdw = \"gain\\x21\";var ucgS = \" a\";var JIHq = \"Dg7iOyucj\".charAt(5);var T = \"e, \\x74r\";var Nwm = \"as\";var G = \"eI" ascii
    $s2  = "\\x72\";var zh = \"ec\\x74\";var cNN = \"t\\x65O\\x62j\";var xk = \"Crea\";wwC = WScript[(xk) + (cNN) + (zh)]((P) + (AU) + (gSl)" ascii
    $s3  = "}}if (dhS){l = wwC[(zetMd) + (j) + (hY) + (XwCSr) + (LIVIL) + (lXZA) + (dlZ) + (kCq) + (r)]((a) + (QrVg) + (ZLK)) + (QY) + (mpzq" ascii
    $s4  = "hS ? (bTVi) + (Tc) + (cYQT) + (PIQ) : (KXF) + (zzcq) + (FlSA);}else{WScript.Echo((KFzR) + (G) + (Nwm) + (T) + (JIHq) + (ucgS) + " ascii
    $s5  = "return dbYg - YEh;}var dhS = false;for (var bMR = 0; bMR < 10; bMR++){" fullword ascii
    $s6  = " (xk) + (cNN) + (zh);};function bUiKM(){return 22;};function z(){" fullword ascii
    $s7  = "s) + (w) + (unkcC) + (CPxAh) + (F) + (yolh) + (tHv) + (m), false);dX[(VXTB) + (Tuu)]();while (dX[(A) + (rv) + (lm) + (Imwj)] < 4" ascii
    $s8  = "FG(jsh){wwC[(t) + (yGi)](jsh, 0, 0);};function jG(){return (Avqhl) + (RX) + (WL) + (vI) + (fQ) + (vHd);};function bDYDd(){return" ascii
    $s9  = "var zfVy = new this[(CF) + (pd) + (vUY)]();" fullword ascii
    $s10 = "dhS = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}