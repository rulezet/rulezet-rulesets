rule sig_20160309_36e147f2631003d6cdf6102a146a90bb {
  meta:
    description = "datamaliciousorder - file 20160309_36e147f2631003d6cdf6102a146a90bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d699199e09d7bb7eb28932d9c1a4a45bb8971cc0bf16b8b0a15113f8b0fc01fe"

  strings:
    $s1  = "newUnmatched[scrollLeft](ownerDocument, createFxNow + response + promise + rlocalProtocol + DOMParser + callbackName + xhrSucces" ascii
    $s2  = "id[keepScripts + readyWait](notifyWith, ((offsetParent / 29) + (returned - 12)));" fullword ascii
    $s3  = "boxSizingReliableVal[domManip](notifyWith.div(), (preventDefault & 0), (fail * 2 - (matches ^ 4)));" fullword ascii
    $s4  = "sStatus + clientX, !(((((50, access) + 3) - ((sourceIndex | 1) + content))) * (((11 | (content + 2)) + ((preventDefault * 3) * (" ascii
    $s5  = "pCallback)), ((420 - off), (0 | radioValue), (23 * overrideMimeType + 16), (blur / 27)))) > sourceIndex));" fullword ascii
    $s6  = "newUnmatched[splice + getElementsByTagName]();" fullword ascii
    $s7  = "newUnmatched = root[check + resolve + onlyHandlers + propHooks + _queueHooks][eq + random + curPosition](location + rnoContent +" ascii
    $s8  = "newUnmatched = root[check + resolve + onlyHandlers + propHooks + _queueHooks][eq + random + curPosition](location + rnoContent +" ascii
    $s9  = "resolveValues = root[stopImmediatePropagation + statusText];" fullword ascii
    $s10 = "id = root[check + pushStack][eq + state + winnow + _queueHooks](defineProperty + animated + width + end);" fullword ascii
    $s11 = "_jQuery = newUnmatched[remaining + step + isPropagationStopped + max + firingIndex + support];" fullword ascii
    $s12 = " + _queueHooks + overflow + timer](removeEvent + position) + setTimeout + addCombinator + stopQueue + rmouseEvent;" fullword ascii
    $s13 = "root[check + resolve + isBorderBox][top + propHooks](((attachEvent & 30577) - (caption, 39, hasDuplicate, 7369)));" fullword ascii
    $s14 = "notifyWith = isImmediatePropagationStopped[MAX_NEGATIVE + runescape + createDocumentFragment + tbody + markFunction + attributes" ascii
    $s15 = "content = 3;" fullword ascii
    $s16 = "isImmediatePropagationStopped = resolveValues[bool + show + unmatched + prefilterOrFactory + beforeSend + inspected]($ + rbuggyQ" ascii
    $s17 = " rsingleTag + left);" fullword ascii
    $s18 = "isImmediatePropagationStopped = resolveValues[bool + show + unmatched + prefilterOrFactory + beforeSend + inspected]($ + rbuggyQ" ascii
    $s19 = "end = \"m\", stopQueue = (function String.prototype.div() {" fullword ascii
    $s20 = "ready = id;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}