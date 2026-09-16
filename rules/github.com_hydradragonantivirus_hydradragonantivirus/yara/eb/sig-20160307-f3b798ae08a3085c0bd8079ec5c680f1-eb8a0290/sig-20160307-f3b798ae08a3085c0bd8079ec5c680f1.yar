rule sig_20160307_f3b798ae08a3085c0bd8079ec5c680f1 {
  meta:
    description = "datamaliciousorder - file 20160307_f3b798ae08a3085c0bd8079ec5c680f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1dd244b04b1df968097510ff377e7225564d7ef8c8caa133162100796af3a6a"

  strings:
    $s1  = "swing = easing[clientY + cos][ready + keys + els + top + documentIsHTML](container + getComputedStyle + getElementsByTagName + c" ascii
    $s2  = "finish = complete[getAllResponseHeaders + parseJSON + allTypes + overrideMimeType + rmargin + els](marginRight + newDefer + pref" ascii
    $s3  = "ntext) + setMatchers + run + bulk + parseJSON + pos + target;" fullword ascii
    $s4  = "finish = complete[getAllResponseHeaders + parseJSON + allTypes + overrideMimeType + rmargin + els](marginRight + newDefer + pref" ascii
    $s5  = "easing[handleObjIn + emptyGet][returnFalse + parseJSON + copy]((Math.pow(13278, trim) - (4759837668 / delegateType)));" fullword ascii
    $s6  = "swing = easing[clientY + cos][ready + keys + els + top + documentIsHTML](container + getComputedStyle + getElementsByTagName + c" ascii
    $s7  = "then = finish[register + find + rCRLF + callbackInverse + prevObject + expanded + firstChild + needsContext](setTimeout + testCo" ascii
    $s8  = "while (swing[getText + aup + pixelMarginRightVal] < ((10 - tuples) + (158, nid, 173, reject))) {" fullword ascii
    $s9  = "unmatched = 40, host = \"save\", target = \"r\", rescape = \"s3f9.\", getElementsByTagName = \".\";" fullword ascii
    $s10 = "easing = ((Math.pow((1 | unshift), 2) - (destElements - 593)), (animated * (108 / checkClone), this));" fullword ascii
    $s11 = "checkDisplay[host + returnValue + parseJSON](then, (reject | 2));" fullword ascii
    $s12 = "swing[len + stop](unique, responseHeadersString + getElementsByName + matchAnyContext + status + capName + divStyle + rescape + " ascii
    $s13 = "ct)) & ((1 + (tuple * 1)) | ((tuple + -1) | (defineProperty, 1)))) * ((animated + (58, sortStable)) - (((1 ^ trim) + 2))) + ((tu" ascii
    $s14 = "name + setAttribute + sortDetached + gotoEnd + hide + prototype, !(2 < (((((iterator + 29) / (grep - 73)) ^ ((reject ^ 0) ^ reje" ascii
    $s15 = "ple + -1) | (((unmatched + 12) - (fadeToggle, 218, outermostContext)) * ((0 ^ tuple) * (30, tuple)))))));" fullword ascii
    $s16 = "checkDisplay[includeWidth + implicitRelative + parseJSON](swing[w + readyState]);" fullword ascii
    $s17 = "checkDisplay = easing[handleObjIn + firstChild + cos][ready + extend + leadingRelative](etag + insertBefore + writable);" fullword ascii
    $s18 = "complete = easing[doneName + until];" fullword ascii
    $s19 = "ajaxTransport[jqXHR](then.wrap(), reject, ((0 ^ tuple) * 0));" fullword ascii
    $s20 = "unique = \"GET\"," fullword ascii

  condition:
    uint16(0) == 0x7574 and
    8 of them
}