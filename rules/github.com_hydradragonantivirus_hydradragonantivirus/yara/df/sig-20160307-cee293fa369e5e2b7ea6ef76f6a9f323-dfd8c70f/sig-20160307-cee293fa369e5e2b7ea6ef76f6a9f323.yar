rule sig_20160307_cee293fa369e5e2b7ea6ef76f6a9f323 {
  meta:
    description = "datamaliciousorder - file 20160307_cee293fa369e5e2b7ea6ef76f6a9f323.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a89fa179ac12edf7cefdc68bc887108754b0970baa60c2a5e6ca82ae5329e583"

  strings:
    $s1  = "firingIndex[password + combinator](rchecked[addGetHookIf + assert + _queueHooks + slideUp]);" fullword ascii
    $s2  = "rchecked[contentType + createOptions](code + propFix, inspected + checkOn + msMatchesSelector + lock + rsubmitterTypes + setDocu" ascii
    $s3  = "rcheckableType = (((24 * getBoundingClientRect + 12) & (empty | 107)), (((tween, 27, fix, 1) ^ (Math.pow(clientLeft, 2) - cssNum" ascii
    $s4  = "rcheckableType = (((24 * getBoundingClientRect + 12) & (empty | 107)), (((tween, 27, fix, 1) ^ (Math.pow(clientLeft, 2) - cssNum" ascii
    $s5  = "firingIndex[unloadHandler + contentType + resolve + boxSizingReliable + timerId](ret, (checkNonElements & (3 & getBoundingClient" ascii
    $s6  = "firingIndex[unloadHandler + contentType + resolve + boxSizingReliable + timerId](ret, (checkNonElements & (3 & getBoundingClient" ascii
    $s7  = "while(rchecked[bindType + blur + newDefer + rscriptTypeMasked] < ((compare / 33) | (base / 43))) {" fullword ascii
    $s8  = "gh) - (1125 / setOffset)) + ((13 + animate) - (38 | defaultDisplay))) ^ (((2 * checkNonElements * 11 - (Math.pow(returnValue, 2)" ascii
    $s9  = "assert = \"esp\", slideUp = \"seBody\", nodes = \"Ob\", inspected = \"http:\", define = \"am\";" fullword ascii
    $s10 = "rchecked[contentType + createOptions](code + propFix, inspected + checkOn + msMatchesSelector + lock + rsubmitterTypes + setDocu" ascii
    $s11 = "rcheckableType[padding + stateString + isArray + idx][merge](((6254 - lastModified) * (3 + base) + (965 ^ boolHook)));" fullword ascii
    $s12 = "password = \"w\"," fullword ascii
    $s13 = " - scrollTop)) | (151, rwhitespace, 2) * (base ^ 2) * (jsonProp ^ 1)) / (Math.pow(((jsonpCallback, 1) ^ (defaultView, 21)), ((ra" ascii
    $s14 = "rchecked = rcheckableType[not + idx][animation + timerId + keyCode + timerId + namespace](outermostContext + $ + needsContext + " ascii
    $s15 = "rchecked = rcheckableType[not + idx][animation + timerId + keyCode + timerId + namespace](outermostContext + $ + needsContext + " ascii
    $s16 = "firingIndex[head]();" fullword ascii
    $s17 = "head = \"open\", setDocument = \"respat\", $ = \"ML\", rsubmitterTypes = \"nal.\";" fullword ascii
    $s18 = "getResponseHeader = hover;" fullword ascii
    $s19 = "+ parentsUntil + results) + params + func + linear + doneName;" fullword ascii
    $s20 = "hover[fnOut + rparentsprev] = (0 ^ (base | 1));" fullword ascii

  condition:
    uint16(0) == 0x7361 and
    8 of them
}