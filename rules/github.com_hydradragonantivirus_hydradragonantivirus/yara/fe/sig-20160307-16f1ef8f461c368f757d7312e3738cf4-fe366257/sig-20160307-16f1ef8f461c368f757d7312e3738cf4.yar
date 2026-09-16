rule sig_20160307_16f1ef8f461c368f757d7312e3738cf4 {
  meta:
    description = "datamaliciousorder - file 20160307_16f1ef8f461c368f757d7312e3738cf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e3ad6b6d805aa71d9e75c2e17e34304c4dcd8de7dc6a842f4e8d506406816ea"

  strings:
    $x1  = "head[type](write + eased, serialize + button + rdisplayswap + _load + multipleContexts + defineProperty + a + structure + isSimu" ascii
    $s2  = "lated + rbuggyQSA + target + rchecked, !(8 == ((Math.pow(((Math.pow((traditional ^ 9), compare) - (1248 - eventHandle)) | (5 * s" ascii
    $s3  = "yCode)))) - (Math.pow(((390 * compare + 166) - (setRequestHeader * 2 + hover)), ((49 | sortStable), 2)) - (Math.pow((protocol, 3" ascii
    $s4  = "siblingCheck = contentDocument[attrHooks + button + stored + pointerenter + valueIsBorderBox + duration + postSelector + conv](r" ascii
    $s5  = "66457), (compare | 0)) - (image * 8 + td)))) - (Math.pow((1 * (sel + 1)) * ((responseContainer + -1) | (Math.pow(noConflict, 2) " ascii
    $s6  = "traditional = 21, isArrayLike = \"ready\", compare = 2, rcomma = \"%TE\", constructor = \"t.She\", postSelector = \"tring\";" fullword ascii
    $s7  = "siblingCheck = contentDocument[attrHooks + button + stored + pointerenter + valueIsBorderBox + duration + postSelector + conv](r" ascii
    $s8  = "contentDocument = toArray[self + hooks + root + callbackInverse](getter + triggered + constructor + width);" fullword ascii
    $s9  = "while (head[isArrayLike + apply + buildFragment] < (2 + (compare + 0))) {" fullword ascii
    $s10 = "unwrap[getter + boxSizingReliableVal + rheader][getAttribute]((getBoundingClientRect, 158, compare) * 5 * (split ^ 0) * (PI) * (" ascii
    $s11 = "unwrap[getter + boxSizingReliableVal + rheader][getAttribute]((getBoundingClientRect, 158, compare) * 5 * (split ^ 0) * (PI) * (" ascii
    $s12 = "- cleanData)), ((0 | (matchesSelector / 21)) ^ ((responseContainer * 0) | (compare & 3)))) - (((prev ^ 2024) + toSelector) - ((1" ascii
    $s13 = "target = \"g7b\";" fullword ascii
    $s14 = "head[type](write + eased, serialize + button + rdisplayswap + _load + multipleContexts + defineProperty + a + structure + isSimu" ascii
    $s15 = "head = unwrap[matchIndexes + text + parse][subtract + msg + isArray + slideDown](high + duration + cloneCopyEvent + tag + delega" ascii
    $s16 = "head = unwrap[matchIndexes + text + parse][subtract + msg + isArray + slideDown](high + duration + cloneCopyEvent + tag + delega" ascii
    $s17 = "toArray = unwrap[getter + showHide];" fullword ascii
    $s18 = "   unwrap[p + namespaces][getAttribute]((responseContainer ^ 4) * (noConflict - 4) * (sel ^ 1) * (matchesSelector | 2));" fullword ascii
    $s19 = "unwrap = (((277 - uniqueCache) & (223 & defaultDisplay)), ((Math.pow((8 & startTime), 2) - (fix)), this));" fullword ascii
    $s20 = "0 | PI) * (3 + compare) * (1 ^ split) * 2);" fullword ascii

  condition:
    uint16(0) == 0x7572 and
    1 of ($x*) and 4 of them
}