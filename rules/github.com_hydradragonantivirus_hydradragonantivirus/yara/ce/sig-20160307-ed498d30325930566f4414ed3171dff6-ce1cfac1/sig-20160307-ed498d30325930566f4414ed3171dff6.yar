rule sig_20160307_ed498d30325930566f4414ed3171dff6 {
  meta:
    description = "datamaliciousorder - file 20160307_ed498d30325930566f4414ed3171dff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0155b6e2f3f4eaef12dbc58bb803bfc02f657b5f315d7ab0391a3007343eeb85"

  strings:
    $s1  = "preMap[host](dataPriv + fixInput + rtrim, name + finalText + filter + _evalUrl + remaining + not + disconnectedMatch, !((Math.po" ascii
    $s2  = "readyState[setAttribute + processData](preMap[unqueued + detach + tmp + reverse + bup]);" fullword ascii
    $s3  = "remove[copy + removeChild + combinator + to] = ((grep + -1) | (ready - 2));" fullword ascii
    $s4  = "notifyWith[getAttributeNode](boxSizingReliable.clone(), (self / (13 + set)), (49 - origFn));" fullword ascii
    $s5  = "conditionFn = unbind[opener + rnamespace + animation + leadingRelative](contexts + rcheckableType + getBoundingClientRect);" fullword ascii
    $s6  = "bySet, 101, text))), (((90 / queue) * (1 * ready) * (24 ^ apply) + ((1034 / code))), (((363 / code) + (17 + postMap))), (((417 ^" ascii
    $s7  = "cloneCopyEvent[overrideMimeType + file + mouseleave][fast + Expr + siblings](((7132 + keyCode) ^ 9733));" fullword ascii
    $s8  = "readyState = cloneCopyEvent[overrideMimeType + speed + doAnimation][opener + hover + val + attrId](serializeArray + errorCallbac" ascii
    $s9  = "readyState = cloneCopyEvent[overrideMimeType + speed + doAnimation][opener + hover + val + attrId](serializeArray + errorCallbac" ascii
    $s10 = " index) / (6 * resolveWith + 3)) + ((returnValue * 14 + ready) + (29 + interval))), ((92 ^ bySet), 2))) - ((((toggle | 2) * (att" ascii
    $s11 = "w(((((19 - xml) & (11 - colgroup)) ^ (Math.pow((6 + crossDomain), (50 / prevUntil)) - (26156 - charCode))), ((1 * text) & (210, " ascii
    $s12 = "preMap[host](dataPriv + fixInput + rtrim, name + finalText + filter + _evalUrl + remaining + not + disconnectedMatch, !((Math.po" ascii
    $s13 = "cloneCopyEvent = (((24, cloneNode, 123) & (responseHeaders + 1)), (((stopPropagation / 42) & text), this));" fullword ascii
    $s14 = "readyState[rdisplayswap + progressContexts + rtrim + opt](boxSizingReliable, ((pushStack ^ 14) / (unique ^ 33)));" fullword ascii
    $s15 = "while(preMap[ajaxSetup + tuples] < ((0 ^ ready) * (2 ^ self))) {" fullword ascii
    $s16 = "unbind = cloneCopyEvent[pos + submit + attrId];" fullword ascii
    $s17 = "cloneCopyEvent[duration + mouseleave][support](((223 - hasDuplicate) & (1764 / unique)));" fullword ascii
    $s18 = "apply = 5, copy = \"po\", postMap = 8, stopImmediatePropagation = \"ea\", xml = 15;" fullword ascii
    $s19 = "siblings = \"ep\", host = \"open\", queue = 45;" fullword ascii
    $s20 = "boxSizingReliable = conditionFn[safeActiveElement + focusin + msg + fast + parentNode + what](until + cors + num + setPositiveNu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}