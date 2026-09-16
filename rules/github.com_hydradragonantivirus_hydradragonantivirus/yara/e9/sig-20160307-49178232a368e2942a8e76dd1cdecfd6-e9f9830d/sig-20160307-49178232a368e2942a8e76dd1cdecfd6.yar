rule sig_20160307_49178232a368e2942a8e76dd1cdecfd6 {
  meta:
    description = "datamaliciousorder - file 20160307_49178232a368e2942a8e76dd1cdecfd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f48e3850786882c2c2214bd29cf09715ebb791d4090ffee98d680693ea1aaf2"

  strings:
    $s1  = "tick[unbind](delegateTarget, text + pseudos + linear + overflowY + setPositiveNumber + boolHook + origFn + lang + initialInUnit " ascii
    $s2  = "tick[unbind](delegateTarget, text + pseudos + linear + overflowY + setPositiveNumber + boolHook + origFn + lang + initialInUnit " ascii
    $s3  = "getter = ((7 * _$ * 2 * _default | (40 / constructor)), (((67, Deferred, 186, Symbol), (64 ^ id), (Math.pow(146, _$) - 21110), (" ascii
    $s4  = " 44))) & ((height ^ (233, boxSizingReliable, 102)) / ((dataShow | 2) * (postMap - 13) + (rfocusMorph, 1)))) ^ (Math.pow((Math.po" ascii
    $s5  = "getter = ((7 * _$ * 2 * _default | (40 / constructor)), (((67, Deferred, 186, Symbol), (64 ^ id), (Math.pow(146, _$) - 21110), (" ascii
    $s6  = "contains[to + win + props + msg + speeds + rnoContent](handler, ((18 * _$ + 8) - (dir & 47)));" fullword ascii
    $s7  = "+ properties + send + isEmptyObject + bubbleType, !((((((3120 / cssFn) / 3 * _$ * 2 * _$ * 2) ^ ((image * 1) + (getClientRects -" ascii
    $s8  = "getter[swap + allTypes + childNodes][lname + win + node](((3017 & dequeue) ^ (3264 ^ addCombinator)));" fullword ascii
    $s9  = "w((pnum + 3), (fns / 33)) - rnotwhite), ((0 / (image * 44)) | (_$ & (72 / nodeName)))) - ((Math.pow(29, _$) - 800) & (a, 45)))) " ascii
    $s10 = "getter[preDispatch + rneedsContext + childNodes][teardown + matcherIn](((cleanData * 7 + param) ^ (48 + prevObject)));" fullword ascii
    $s11 = "text = \"http:\";" fullword ascii
    $s12 = "tick = getter[notifyWith + speeds + childNodes][leadingRelative + ignored + list + classes](readyState + finalDataType + Callbac" ascii
    $s13 = "tick = getter[notifyWith + speeds + childNodes][leadingRelative + ignored + list + classes](readyState + finalDataType + Callbac" ascii
    $s14 = "trim[initial + origFn + src] = ((1 + -image));" fullword ascii
    $s15 = "tick[onlyHandlers + qsaError]();" fullword ascii
    $s16 = "handler = responseType[isReady + matchers + origFn + keyHooks + win + m + classes + noBubble](parentNode + safeActiveElement + r" ascii
    $s17 = "handler = responseType[isReady + matchers + origFn + keyHooks + win + m + classes + noBubble](parentNode + safeActiveElement + r" ascii
    $s18 = "contains = getter[preDispatch + replaceWith + classes][rparentsprev + setter + addBack](tuples + createDocumentFragment + subord" ascii
    $s19 = "contains = getter[preDispatch + replaceWith + classes][rparentsprev + setter + addBack](tuples + createDocumentFragment + subord" ascii
    $s20 = "stopped = getter[notifyWith + createCache + classes];" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}