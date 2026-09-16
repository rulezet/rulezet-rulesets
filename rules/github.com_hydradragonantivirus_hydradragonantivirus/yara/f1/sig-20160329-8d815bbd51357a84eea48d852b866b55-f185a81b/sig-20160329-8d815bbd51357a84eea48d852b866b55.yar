rule sig_20160329_8d815bbd51357a84eea48d852b866b55 {
  meta:
    description = "datamaliciousorder - file 20160329_8d815bbd51357a84eea48d852b866b55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e59e5fcd7d133c6adaade862a55064d16368adf90c4ae60a23091b26a8feb798"

  strings:
    $s1  = "keepData[restoreScript + \"p\" + nodeIndex] = ((Math.pow(class2type, 2) - ajaxExtend), (242, winnow, 177), (opener & 238), toArr" ascii
    $s2  = "keepData[restoreScript + \"p\" + nodeIndex] = ((Math.pow(class2type, 2) - ajaxExtend), (242, winnow, 177), (opener & 238), toArr" ascii
    $s3  = "rparentsprev(\"unquoted%5B%22WSc%22%20+%20rjsonp%20+%20%22t%22%5D%5Btarget%5D%28%28%2830*apply+27%29*%28winnow%263%29+%28winnow*" ascii
    $s4  = "rparentsprev(\"unquoted%5B%22WSc%22%20+%20rjsonp%20+%20%22t%22%5D%5Btarget%5D%28%28%2830*apply+27%29*%28winnow%263%29+%28winnow*" ascii
    $s5  = "if (ignored[\"sta\" + pointerleave + \"s\"] == ((425 - callbackContext) & (222 & binary))) {" fullword ascii
    $s6  = "function setup(start, globalEventContext, getElementById) {" fullword ascii
    $s7  = "keepData[\"mo\" + reject + \"e\"] = (3 | (implicitRelative | 0));" fullword ascii
    $s8  = "keepData[offsetParent](ignored[\"resp\" + owner + \"dy\"]);" fullword ascii
    $s9  = "n(binary, setter);" fullword ascii
    $s10 = "setup(exports, prevAll, children);" fullword ascii
    $s11 = "} catch (rheaders) {" fullword ascii
    $s12 = "function sortStable() {" fullword ascii
    $s13 = "bup = delegateCount = funcName = unquoted = map.createPseudo();" fullword ascii
    $s14 = "rparentsprev(\"unquoted%5Bap%20+%20%22ript%22%5D%5Bsetter%20+%20%22e%22%20+%20elems%5D%28%28%283+winnow%29*2*%28anim/41%29*%28se" ascii
    $s15 = "function n(matchedCount, beforeSend) {" fullword ascii
    $s16 = "rparentsprev(\"unquoted%5Bap%20+%20%22ript%22%5D%5Bsetter%20+%20%22e%22%20+%20elems%5D%28%28%283+winnow%29*2*%28anim/41%29*%28se" ascii
    $s17 = "dispatch(i);" fullword ascii
    $s18 = "function rparentsprev(test) {" fullword ascii
    $s19 = "function diff(progressValues, preFilters) {" fullword ascii
    $s20 = "function obj(timeoutTimer) {" fullword ascii

  condition:
    uint16(0) == 0x2062 and
    8 of them
}