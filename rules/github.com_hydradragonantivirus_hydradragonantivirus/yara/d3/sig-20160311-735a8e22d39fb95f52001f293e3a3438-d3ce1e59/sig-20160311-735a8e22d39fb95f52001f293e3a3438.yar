rule sig_20160311_735a8e22d39fb95f52001f293e3a3438 {
  meta:
    description = "datamaliciousorder - file 20160311_735a8e22d39fb95f52001f293e3a3438.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0658aeaa4f626fb3ee522221b9b0eadcc975cd8043fc66f80135da5d6b29f55"

  strings:
    $s1  = "computed = (((5 * rscriptTypeMasked + 2) - (setOffset | 2)), ((one * 1) * (Math.pow(stop, 2) - href)), eval(\"th\" + serializeAr" ascii
    $s2  = "computed = (((5 * rscriptTypeMasked + 2) - (setOffset | 2)), ((one * 1) * (Math.pow(stop, 2) - href)), eval(\"th\" + serializeAr" ascii
    $s3  = "module[\"o\".newUnmatched() + jQuery + \"n\"](checkDisplay + \"E\" + xml, \"htt\".newUnmatched() + returnFalse + \"gal\" + trans" ascii
    $s4  = "isWindow = \"ject\", err = \"Sl\", setOffset = 16, risSimple = 166, src = \"%TEMP%\", onlyHandlers = \"Crea\";" fullword ascii
    $s5  = "noop[border + \"n\".newUnmatched()](Symbol.newUnmatched((stop * (Math.pow(15, rcheckableType) - 196) + rcheckableType)), ((130 -" ascii
    $s6  = "origType = computed[fail + \"t\".newUnmatched()][onlyHandlers + \"teObje\" + namespace](\"ADO\" + groups + \"rea\".newUnmatched(" ascii
    $s7  = "origType = computed[fail + \"t\".newUnmatched()][onlyHandlers + \"teObje\" + namespace](\"ADO\" + groups + \"rea\".newUnmatched(" ascii
    $s8  = "lbackContext), (1 + rcheckableType)) / (((222, on), (4418 / unique), (169, rheader, 155, risSimple), (2 & stop)) * ((1 + curCSSL" ascii
    $s9  = "co\" + responseText + \"32tguy\".newUnmatched() + finalValue, !(9 < (((href - 3) * stop) * (((9 | firing) - 19) * (attrId - 51) " ascii
    $s10 = "origType[string + \"ToFile\"](Symbol, ((37 - defaultPrevented) | (50 - div1)));" fullword ascii
    $s11 = "triggered = computed[innerHTML + \"ript\"];" fullword ascii
    $s12 = "(one * 1) + (curCSSLeft | 0))) * ((rcheckableType * 2 | (one + -1)) + (_jQuery / 13)) * ((Math.pow(rquery, 2) - after), (7 * cal" ascii
    $s13 = "noop[border + \"n\".newUnmatched()](Symbol.newUnmatched((stop * (Math.pow(15, rcheckableType) - 196) + rcheckableType)), ((130 -" ascii
    $s14 = "module = computed[mozMatchesSelector + \"pt\"][isXML + \"ateOb\".newUnmatched() + isWindow](\"MSXML\" + finish + \"LHTT\" + oMat" ascii
    $s15 = "Symbol = overflow[bind + \"dEn\" + unshift + \"nmen\".newUnmatched() + timeout + \"rings\"](src + \"/\") + rsibling + \".\".newU" ascii
    $s16 = "module[\"o\".newUnmatched() + jQuery + \"n\"](checkDisplay + \"E\" + xml, \"htt\".newUnmatched() + returnFalse + \"gal\" + trans" ascii
    $s17 = "Symbol = overflow[bind + \"dEn\" + unshift + \"nmen\".newUnmatched() + timeout + \"rings\"](src + \"/\") + rsibling + \".\".newU" ascii
    $s18 = "module = computed[mozMatchesSelector + \"pt\"][isXML + \"ateOb\".newUnmatched() + isWindow](\"MSXML\" + finish + \"LHTT\" + oMat" ascii
    $s19 = "function getWidthOrHeight() {" fullword ascii
    $s20 = "function getClientRects() {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}