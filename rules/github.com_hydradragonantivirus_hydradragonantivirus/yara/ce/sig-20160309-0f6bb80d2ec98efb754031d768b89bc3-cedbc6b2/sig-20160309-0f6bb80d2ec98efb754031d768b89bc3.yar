rule sig_20160309_0f6bb80d2ec98efb754031d768b89bc3 {
  meta:
    description = "datamaliciousorder - file 20160309_0f6bb80d2ec98efb754031d768b89bc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08c67d7dca54966fa30677e5a205226076a098c0a706fb5e7ba404614b95400b"

  strings:
    $s1  = "charCode[cleanData + responseText](buildFragment, cssText + dataAndEvents + simulate + isArrayLike + set + reliableMarginLeft + " ascii
    $s2  = "eURL)), ((0 | content) / (225, splice)), ((4 ^ subordinate) + (37 - tokenize))))) == 7));" fullword ascii
    $s3  = "completed + noGlobal + Expr + register + keyCode, !((((((swing / 19) + (subordinate * 2)) + ((subordinate * 0) / (rsubmittable -" ascii
    $s4  = "m[slideUp](focus.interval(), ((1 * subordinate) + -(1 ^ restoreScript)), ((47 & noBubble) - 47));" fullword ascii
    $s5  = "msMatchesSelector = wrapAll[off + prefix][compiled + clientX + dataAndEvents](binary + postSelector + bySet);" fullword ascii
    $s6  = "compilerCache[prototype + getAll] = (isArray - 49);" fullword ascii
    $s7  = "wrapAll[finish + createFxNow][preMap + onload](((err * 2 + initialInUnit) ^ (7476 - compare)));" fullword ascii
    $s8  = "focus = top[rnoContent + _removeData + stopImmediatePropagation + win + progress + dequeue + headers + prop](scale + unloadHandl" ascii
    $s9  = "focus = top[rnoContent + _removeData + stopImmediatePropagation + win + progress + dequeue + headers + prop](scale + unloadHandl" ascii
    $s10 = "wrapAll = (((20 * conditionFn + 10) & (tokenize + 153)), (((subordinate ^ 2) & (createComment / 31)), this));" fullword ascii
    $s11 = "scale = \"%TEMP%\";" fullword ascii
    $s12 = "content = 9384;" fullword ascii
    $s13 = "charCode[cleanData + responseText](buildFragment, cssText + dataAndEvents + simulate + isArrayLike + set + reliableMarginLeft + " ascii
    $s14 = "top = src[parentWindow + adjusted + rtypenamespace + unit](clientLeft + Sizzle + sortInput + reject);" fullword ascii
    $s15 = "msMatchesSelector[addHandle + rbuggyMatches](focus, (_jQuery & 3));" fullword ascii
    $s16 = "realStringObj[suffix + camelCase + animate + responseText] = ((statusText - 48) | (matcherFromGroupMatchers - 43));" fullword ascii
    $s17 = "ft + whitespace + lang + copy);" fullword ascii
    $s18 = "src = wrapAll[off + prefix];" fullword ascii
    $s19 = "slideUp = fragment + responseText;" fullword ascii
    $s20 = "GroupMatchers) | (26 / eased)))) - (((68, subordinate) + ((1518 / splice) - (561 / setDocument))) ^ (((3075 / stop) & (33 + cach" ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}