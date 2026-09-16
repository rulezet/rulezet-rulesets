rule sig_20160317_dd802bf10e2f9c44ae9668a9ec24620f {
  meta:
    description = "datamaliciousorder - file 20160317_dd802bf10e2f9c44ae9668a9ec24620f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50243bebe000d97e20743839df21d138eb679e3ec5d778878343920ad323209c"

  strings:
    $x1 = "var SQnrO = \"ain!\";var xO = \"\\x61g\";var YynCM = \"\\x72\\x79 \";var PkRao = \"se, \\x74\";var WidXA = \"nnsLaT\".charAt(4);" ascii
    $s2 = "}}if (GfVs){pGb = sEEiI[(iHwRk) + (H0) + (VdZ) + (Tib) + (pnG) + (ZmGu) + (FcH) + (F)]((qBYmw) + (pfug)) + (fbbJ) + (Cjqtq) + (S" ascii
    $s3 = "return PTq - hEWtA;}var GfVs = false;for (var qR = 0; qR < w() * 1; qR++){" fullword ascii
    $s4 = "plGt)]((BuJWj) + (W) + (mJNJU) + (KI));function Q(EO){sEEiI[(Bfuk)](EO, 0, 0);};function Irn(){return (erqDS) + (Z) + (gpb) + (x" ascii
    $s5 = " (aseFt) + (QLo) + (CusCR) + (xbzJs) + (ztmeb) + (g) + (xOFuJ) + GfVs ? (BMx) + (KL) + (Vb) : (ywL) + (ZTi) + (jmggD);}else{WScr" ascii
    $s6 = "(fh), (EXw) + (e) + (tXo) + (NeGC) + (h) + (Y) + (qtHZ) + (cHGkN) + (Ezt) + (WiL) + (uR) + (G), false);sbFz[(bJndl)]();while (sb" ascii
    $s7 = "xF) + (NkQ);};function SNz(){return (tXH) + (eiO) + (eq) + (plGt);};function w(){return 22;};function GGb(){" fullword ascii
    $s8 = "GfVs = true;" fullword ascii
    $s9 = "var j = new this[(fANIZ)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}