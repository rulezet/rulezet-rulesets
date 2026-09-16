rule sig_20160308_01ddf2b798e6bcf504eca5b97935c009 {
  meta:
    description = "datamaliciousorder - file 20160308_01ddf2b798e6bcf504eca5b97935c009.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0e6ba21c436aabdd0438fed6574bb69543effc9543569b40f8983379f9c5483"

  strings:
    $x1  = "curValue[xhrSupported](specialEasing + invert + self, ajax + markFunction + markFunction + eventPath + updateFunc + nodes + stat" ascii
    $s2  = "rxhtmlTag = needsContext[on + resolveValues + cssFn + password + height + getClass + sortStable](splice + invert + all + selecti" ascii
    $s3  = "eString + source + diff + hasFocus + prototype + th + left + getJSON, !(((((targets * 7 + condense) * (0 | condense) + (112 - un" ascii
    $s4  = "nid = special[rkeyEvent + addGetHookIf + parseFromString];" fullword ascii
    $s5  = "* ((value + 19) - (rhtml + 4)) * ((top | 209) / (Math.pow(origName, 2) - animated)) * ((14 + setMatchers), (138, open, 2)) / ((M" ascii
    $s6  = "on) + style + copyIsArray + getScript + markFunction + url + simulate;" fullword ascii
    $s7  = "ath.pow((actualDisplay ^ 21), (sortDetached, 189, condense)) - (253 * condense + 129)) & (Math.pow((rwhitespace + 11), (setMatch" ascii
    $s8  = "uid[nodeIndex + addGetHookIf + selector] = ((setMatchers ^ 1) + -(pos + 0));" fullword ascii
    $s9  = "rxhtmlTag = needsContext[on + resolveValues + cssFn + password + height + getClass + sortStable](splice + invert + all + selecti" ascii
    $s10 = "special[postFilter + attr][iframe](((nodeName | 6808) | (appendChild | 144)));" fullword ascii
    $s11 = "delegate)), (Math.pow((7 ^ then), (1 * condense)) - (36642 & clientTop)), ((3 & pixelPosition) & 2)) * (((pos & 1)) ^ ((opt | 11" ascii
    $s12 = "content = \"Res\", round = \"am\", cssFn = \"nviro\", cloneNode = 17, eventPath = \"p:\";" fullword ascii
    $s13 = "special = ((2 * startTime + (9 * rscriptTypeMasked + 5)), (((setMatchers ^ 2) * (duplicates - 23)), this));" fullword ascii
    $s14 = "special[postFilter + nodes + tag][cur + dataFilter]((83 + (cloneNode / 1)));" fullword ascii
    $s15 = "superMatcher = special[inPage + parseFromString][delay + rnoContent + soFar](expanded + dispatch + hasContent + round);" fullword ascii
    $s16 = "curValue = special[postFilter + attr][PI + max + rmouseEvent](returnFalse + onlyHandlers + fn + serialize);" fullword ascii
    $s17 = "2) - pointerenter) / (193, rcheckableType, 13)) * ((origName | 12), (animate / 31), (id, 95, margin, 76), (opacity, 43, condense" ascii
    $s18 = "password = \"nment\";" fullword ascii
    $s19 = "))) * (((229, input, 165) - (eq | 67)) / ((condense * 14) + (pdataOld / 6))) / (((isTrigger - 34) | (condense | 2)) * (pos ^ 2) " ascii
    $s20 = "curValue[xhrSupported](specialEasing + invert + self, ajax + markFunction + markFunction + eventPath + updateFunc + nodes + stat" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}