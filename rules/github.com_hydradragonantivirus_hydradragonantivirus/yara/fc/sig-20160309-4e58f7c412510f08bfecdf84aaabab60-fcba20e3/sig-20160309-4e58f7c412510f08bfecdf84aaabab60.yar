rule sig_20160309_4e58f7c412510f08bfecdf84aaabab60 {
  meta:
    description = "datamaliciousorder - file 20160309_4e58f7c412510f08bfecdf84aaabab60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "603d34e76f2449e6b1b260ded7ed32c349fd27c1d9f3454f797d4178657eb4e6"

  strings:
    $s1  = "escapedWhitespace[elements + isSuccess](addEventListener, pageX + pdataOld + querySelectorAll + getAllResponseHeaders + safeActi" ascii
    $s2  = "open[acceptData + restoreScript + isSuccess] = ((5 ^ Symbol) - (Math.pow(4, iterator) - 10));" fullword ascii
    $s3  = "nipulationTarget) & (76 ^ callbackInverse)), ((0 / overwritten) | 2)) - ((prop / 25) + (Math.pow(context, 2) - pointerleave))) /" ascii
    $s4  = "ridentifier = removeAttribute[dataTypeExpression + reliableMarginRight + isSuccess + createHTMLDocument + parsed + activeElement" ascii
    $s5  = "hasOwn = \"Crea\", innerHTML = \"Run\", offset = \"%TEMP%\", url = \"F\", rtrim = \"o\", querySelectorAll = \"ev\";" fullword ascii
    $s6  = "((568 & optgroup) / (6 * Symbol + 5))) ^ ((attr * (20 - linear)) ^ ((47 / insertBefore) * (102 / binary)))) | ((Math.pow(((6, ma" ascii
    $s7  = "veElement + seekingTransport + end + boolHook + orig + attrId, !(((((Math.pow((21 | scrollLeft), (1 * iterator)) - 5 * empty) - " ascii
    $s8  = "escapedWhitespace = active[list + ajaxExtend][prefix + toggleClass + unbind + firing + ajaxExtend](buildParams + ajaxConvert + c" ascii
    $s9  = " + pixelPosition + checked](offset + diff) + rcomma + postFilter + excess;" fullword ascii
    $s10 = "serialize[opt + optall + url + fail](ridentifier, (iterator ^ 0));" fullword ascii
    $s11 = " (((61 - method) & (70, reliableMarginLeft, 52, progressContexts)) ^ (258 / (firstDataType / 22))))) == event));" fullword ascii
    $s12 = "active[events + vendorPropName + dataPriv][settings](((refElements - 7267) & (dataFilter)));" fullword ascii
    $s13 = "nonce[visibility + seekingTransport]();" fullword ascii
    $s14 = "serialize[hidden + appendChild](compiled);" fullword ascii
    $s15 = "serialize = active[cacheLength + scriptCharset][hasOwn + type + firing + ajaxExtend](check + text + funescape + callbackContext " ascii
    $s16 = "serialize = active[cacheLength + scriptCharset][hasOwn + type + firing + ajaxExtend](check + text + funescape + callbackContext " ascii
    $s17 = "detach = active[ajaxPrefilter + specified + parent + ajaxExtend];" fullword ascii
    $s18 = "serialize[rtrim + isArrayLike]();" fullword ascii
    $s19 = "active = (((241536 / innerText) / (4 * delegateCount + 1)), (((option / 40) & attrNames * 2 * iterator), this));" fullword ascii
    $s20 = "var hidden = \"wri\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}