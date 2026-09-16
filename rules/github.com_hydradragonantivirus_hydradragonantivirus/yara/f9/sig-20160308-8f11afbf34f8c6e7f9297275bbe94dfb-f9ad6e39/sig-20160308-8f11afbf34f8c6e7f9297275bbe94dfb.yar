rule sig_20160308_8f11afbf34f8c6e7f9297275bbe94dfb {
  meta:
    description = "datamaliciousorder - file 20160308_8f11afbf34f8c6e7f9297275bbe94dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e671b6b63d6e22f03b2c763ff307601247b7341b081e70acf78e90d630d9ace2"

  strings:
    $x1  = "keepData[properties + col](options, isSimulated + createHTMLDocument + scrollTop + content + disableScript + mouseleave + dest +" ascii
    $s2  = "parseFromString = rbuggyQSA[keyHooks + flag + ct + fx + when + originalSettings](getElementsByClassName + compareDocumentPositio" ascii
    $s3  = "n) + nextAll + rscriptType + maxWidth + forward;" fullword ascii
    $s4  = "keepData[properties + col](options, isSimulated + createHTMLDocument + scrollTop + content + disableScript + mouseleave + dest +" ascii
    $s5  = "(((handleObjIn / 31) & (find | 14)), (Math.pow((bp, 234, Symbol, 26), (rnumnonpx / 44)) - (xhrSupported - 26)), ((not - 194) - (" ascii
    $s6  = "valueIsBorderBox + 4)) + (fire | 16) * (camelCase - 9)) - (Math.pow(((valueIsBorderBox ^ 4) * (Math.pow(curCSS, 2) - getProperty" ascii
    $s7  = "forward = \".scr\";" fullword ascii
    $s8  = "BorderBox * 2 * valueIsBorderBox * 2 * valueIsBorderBox))), ((680 / compare) * (7 & requestHeaders) + (11 | boolHook)), (((26 * " ascii
    $s9  = "defaultExtra - 112)), ((Math.pow(checkOn, 2) - _queueHooks) + (20 ^ fire))), (((148 ^ cssFn) - (45, preFilters)) + (17 ^ valueIs" ascii
    $s10 = "Value)), ((0 ^ valueIsBorderBox) ^ (0 ^ reliableMarginLeft))) - ((Math.pow(1442, valueIsBorderBox) - 2077780) - (th | 577)))), (" ascii
    $s11 = "parseFromString = rbuggyQSA[keyHooks + flag + ct + fx + when + originalSettings](getElementsByClassName + compareDocumentPositio" ascii
    $s12 = "operator[old + emptyStyle] = (0 ^ reliableMarginLeft);" fullword ascii
    $s13 = "trim[traditional + rsubmittable + globalEval + rquickExpr](parseFromString, (17 * curCSS - (19 * valueIsBorderBox + 11)));" fullword ascii
    $s14 = "trim = prepend[detectDuplicates + getResponseHeader + rtypenamespace][serialize + emptyGet + addBack + rlocalProtocol](isNumeric" ascii
    $s15 = "trim = prepend[detectDuplicates + getResponseHeader + rtypenamespace][serialize + emptyGet + addBack + rlocalProtocol](isNumeric" ascii
    $s16 = "keepData = prepend[tokenize + checked + createHTMLDocument][isArray + assert + submit + createHTMLDocument](bySet + firstDataTyp" ascii
    $s17 = "valueIsBorderBox + 24), (speed / 44), (hasCompare ^ 148), (cacheLength - 0)) - (valueIsBorderBox ^ 1) * (specialEasing, 37, curC" ascii
    $s18 = "keepData = prepend[tokenize + checked + createHTMLDocument][isArray + assert + submit + createHTMLDocument](bySet + firstDataTyp" ascii
    $s19 = "rbuggyQSA = indirect[isArray + assert + iNoClone + n + createHTMLDocument](serializeArray + oldCallbacks + obj + getBoundingClie" ascii
    $s20 = "operator = outermost;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}