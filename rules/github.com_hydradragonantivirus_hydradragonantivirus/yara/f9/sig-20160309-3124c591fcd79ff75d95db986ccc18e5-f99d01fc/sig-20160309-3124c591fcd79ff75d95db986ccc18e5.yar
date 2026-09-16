rule sig_20160309_3124c591fcd79ff75d95db986ccc18e5 {
  meta:
    description = "datamaliciousorder - file 20160309_3124c591fcd79ff75d95db986ccc18e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3355712ca2f92059e78ef59fa68fa72879edb7922cd98495faf83ec56e86b0a"

  strings:
    $s1  = "rscriptType = completeDeferred[a + winnow + wrap + unique][cssShow + collection + compare + dataTypeExpression](targets + rsubmi" ascii
    $s2  = "rscriptType = completeDeferred[a + winnow + wrap + unique][cssShow + collection + compare + dataTypeExpression](targets + rsubmi" ascii
    $s3  = "status[nodeIndex + pipe](transports + andSelf, ownerDocument + support + byElement + classes + flag + XMLHttpRequest + url + gua" ascii
    $s4  = "rscriptType[pos + cache + keyHooks](superMatcher, ((constructor & 58) - (escaped * 2 + emptyGet)));" fullword ascii
    $s5  = "2)) - ((selector + 33) / (Math.pow(addEventListener, 2) - splice)))))));" fullword ascii
    $s6  = "status = completeDeferred[callback + err][createComment + results + rkeyEvent + parseXML + unique](isPlainObject + parts + PI + " ascii
    $s7  = "status = completeDeferred[callback + err][createComment + results + rkeyEvent + parseXML + unique](isPlainObject + parts + PI + " ascii
    $s8  = "rsingleTag = \"%TEMP%\", ap = \"open\", self = \"Exp\", raw = 3, parseXML = \"jec\", module = \"B.St\";" fullword ascii
    $s9  = "completeDeferred = ((Math.pow((182 - setAttribute), 2) - uniqueCache), (((0 & trigger) / (25 - splice)), this));" fullword ascii
    $s10 = "status[nodeIndex + pipe](transports + andSelf, ownerDocument + support + byElement + classes + flag + XMLHttpRequest + url + gua" ascii
    $s11 = "superMatcher = setGlobalEval[self + adown + after + activeElement + toggle](rsingleTag + checked) + postSelector + clearTimeout;" ascii
    $s12 = "ranteedUnique + send + fast, !(3 < ((((trigger & 1) & (trigger | 1)) + ((jqXHR ^ 1) + -(trigger ^ 0))) + ((((clientLeft * 12) + " ascii
    $s13 = "before[deepDataAndEvents] = ((1 + -trigger) | 1);" fullword ascii
    $s14 = "status[XMLHttpRequest + set]();" fullword ascii
    $s15 = "completeDeferred[mouseleave + rxhtmlTag + timerId + oldCache][newDefer](((2312 - type) * (100, id, 171, tweeners) + (902 - overf" ascii
    $s16 = "completeDeferred[mouseleave + rxhtmlTag + timerId + oldCache][newDefer](((2312 - type) * (100, id, 171, tweeners) + (902 - overf" ascii
    $s17 = "div1 = completeDeferred[a + JSON + unique];" fullword ascii
    $s18 = "domManip[callbackInverse](superMatcher.rdashAlpha(), ((184 / clientLeft), (75 / trigger), (253 & source), (0 | jqXHR)), ((53, rr" ascii
    $s19 = "pipe = \"n\";" fullword ascii
    $s20 = "rscriptType[what](cloneCopyEvent);" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    8 of them
}