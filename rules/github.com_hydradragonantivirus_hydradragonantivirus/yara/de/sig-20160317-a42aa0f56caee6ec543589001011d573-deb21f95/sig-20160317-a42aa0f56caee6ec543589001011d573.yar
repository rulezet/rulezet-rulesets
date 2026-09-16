rule sig_20160317_a42aa0f56caee6ec543589001011d573 {
  meta:
    description = "datamaliciousorder - file 20160317_a42aa0f56caee6ec543589001011d573.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44fff02abb3a88dffb05a82bf7a46abf2f62dcd893f89ed15f28b037bdf20aac"

  strings:
    $s1 = "var PZyg = \"n!\";var fk = \" \\x61g\\x61i\";var Ver = \"ry\";var DNT = \"t\";var K0 = \"ase\\x2c \";var OHmiS = \"Pl\\x65\";var" ascii
    $s2 = "}}if (L){SrP = tutb[(Ns) + (cIdW) + (tnl) + (KT) + (Zi) + (gRg) + (UJqRk) + (g) + (a)]((rN) + (K) + (m) + (zCt)) + (IkIG) + (u) " ascii
    $s3 = " (M0) + L ? (iEX) + (rG) : (Hy) + (TFC) + (cHLwM);}else{WScript.Echo((OHmiS) + (K0) + (DNT) + (Ver) + (fk) + (PZyg));}" fullword ascii
    $s4 = "return uo - C;}var L = false;for (var pXMS = 0; pXMS < H() * 1; pXMS++){" fullword ascii
    $s5 = "var OfBKc = new this[(qL) + (w)]();" fullword ascii
    $s6 = " (sa) + (A) + (SoWO) + (IHlK);};function wA(){return (xREoS) + (YRLXV) + (qE) + (Lzf);};function H(){return 22;};function qUFxq(" ascii
    $s7 = " + (A0) + (Fjsc) + (cnH) + (MZel) + (y) + (yZrc) + (c) + (Mf) + (Qv), false);wxniO[(OM)]();while (wxniO[(ntcP) + (bL) + (bM) + (" ascii
    $s8 = "qE) + (Lzf)]((TpG) + (Hp) + (KQ) + (XDK));function htty(KuP){tutb[(l) + (bk)](KuP, 0, 0);};function Br(){return (Br0) + (Iamm) +" ascii
    $s9 = "L = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}