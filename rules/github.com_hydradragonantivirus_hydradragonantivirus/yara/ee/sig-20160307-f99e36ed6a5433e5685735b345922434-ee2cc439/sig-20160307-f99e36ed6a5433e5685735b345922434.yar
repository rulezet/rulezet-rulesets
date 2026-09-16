rule sig_20160307_f99e36ed6a5433e5685735b345922434 {
  meta:
    description = "datamaliciousorder - file 20160307_f99e36ed6a5433e5685735b345922434.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c87c51d5ead94ba156c90f5fae5befcb44669cdf5890b53f3e8a90413fa0a9c1"

  strings:
    $s1  = "ajaxTransport[parentOffset + timeoutTimer + setGlobalEval][preMap + border + xhrFields + insertAfter](((1024 | forward) / (Math." ascii
    $s2  = "notifyWith[keepScripts](iterator.valueParts(), ((0 / owner) ^ (0 | b)), (3 * response - (Math.pow(10, selection) - 85)));" fullword ascii
    $s3  = "crossDomain[content + password]();" fullword ascii
    $s4  = "crossDomain[combinator + postSelector + valHooks + removeAttribute](iterator, ((isWindow, 20, risSimple) / (80 - conditionFn)));" ascii
    $s5  = "election & 2) * (owner - 26)) - (((getPropertyValue / 46), selection * 113, (postFinder + 9)) & ((s ^ 149) - (response * 19 + ad" ascii
    $s6  = "while (copyIsArray[filter + rheaders] < ((0 | b) | (9 - response))) {" fullword ascii
    $s7  = "ajaxTransport[parentOffset + timeoutTimer + setGlobalEval][preMap + border + xhrFields + insertAfter](((1024 | forward) / (Math." ascii
    $s8  = "ajaxTransport = (((141 + hooks)), (((1 * addGetHookIf) * (1 * rtypenamespace)), this));" fullword ascii
    $s9  = "crossDomain = ajaxTransport[parentOffset + rhash + head][getClass + file + trim + clearCloneStyle](delegate + events + div1 + so" ascii
    $s10 = "crossDomain = ajaxTransport[parentOffset + rhash + head][getClass + file + trim + clearCloneStyle](delegate + events + div1 + so" ascii
    $s11 = "copyIsArray = ajaxTransport[needsContext + hasOwnProperty][when + visibility + slideDown + clearCloneStyle](state + toSelector +" ascii
    $s12 = "copyIsArray[uniqueSort](pnum, hasDuplicate + insertAfter + wrap + urlAnchor + elements + expando + origName + option + rattribut" ascii
    $s13 = "uccessStatus ^ 60)))) - ((((cors - 38) * (dataAndEvents + 2) + (isPlainObject + 0)) * ((unwrap / 13) * (dataAndEvents + 0)) + (s" ascii
    $s14 = "password = \"en\";" fullword ascii
    $s15 = "status = \"gs\", opt = \"t\", prevAll = \".scr\", getClass = \"Cr\";" fullword ascii
    $s16 = "pow(10, selection) - 88)));" fullword ascii
    $s17 = " rcomma + sourceIndex + setAttribute + mouseHooks + subtract);" fullword ascii
    $s18 = "ajaxTransport[parentOffset + properties + opt][noBubble + slideDown + insertAfter](((context) + (715 * rts + 228)));" fullword ascii
    $s19 = "copyIsArray = ajaxTransport[needsContext + hasOwnProperty][when + visibility + slideDown + clearCloneStyle](state + toSelector +" ascii
    $s20 = "keepScripts = module;" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}