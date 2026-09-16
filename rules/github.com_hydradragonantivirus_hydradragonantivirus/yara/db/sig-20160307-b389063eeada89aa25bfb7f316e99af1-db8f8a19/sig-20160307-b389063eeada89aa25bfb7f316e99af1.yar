rule sig_20160307_b389063eeada89aa25bfb7f316e99af1 {
  meta:
    description = "datamaliciousorder - file 20160307_b389063eeada89aa25bfb7f316e99af1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0ee2211c1f75fa0a85045fe4be7eeff9d4da7ce5b44ad642b4eb407f7b305f3"

  strings:
    $s1  = "globalEventContext[prefilterOrFactory + grep](callback, clearTimeout + eased + readyWait + setOffset + tokens + disableScript + " ascii
    $s2  = "result[box + base][handle + forward]((2 ^ parseJSON) * (2 & push_native) * (Math.pow(4, MAX_NEGATIVE) - 11) * (getBoundingClient" ascii
    $s3  = "result[box + base][handle + forward]((2 ^ parseJSON) * (2 & push_native) * (Math.pow(4, MAX_NEGATIVE) - 11) * (getBoundingClient" ascii
    $s4  = "Sizzle + url + flatOptions, !((((Math.pow(((Math.pow(defaultPrevented, 2) - stopOnFalse) | (17 - overrideMimeType)), ((49 - blur" ascii
    $s5  = "wait[contentType + run + toggle + realStringObj](readyState, (2 * MAX_NEGATIVE - 2));" fullword ascii
    $s6  = "funescape[seed](readyState.Callbacks(), ((booleans * 27) - (Math.pow(rcleanScript, 2) - splice)), ((0 ^ submit) ^ (0 | submit)))" ascii
    $s7  = "funescape[seed](readyState.Callbacks(), ((booleans * 27) - (Math.pow(rcleanScript, 2) - splice)), ((0 ^ submit) ^ (0 | submit)))" ascii
    $s8  = "close[keys] = ((6 - file) & (1 & booleans));" fullword ascii
    $s9  = ")) - ((0 | booleans) * (98 / blur)) * (Math.pow(11, (MAX_NEGATIVE + 0)) - (eventHandle))))));" fullword ascii
    $s10 = "result = (((Math.pow(85, MAX_NEGATIVE) - 7101) | (serializeArray + 106)), (((push_native & 3) + (submit | 0)), this));" fullword ascii
    $s11 = "readyState = oldCache[button + delegateType + accepts + rheader + elems + string + getElementsByClassName + state + to](isLocal " ascii
    $s12 = "readyState = oldCache[button + delegateType + accepts + rheader + elems + string + getElementsByClassName + state + to](isLocal " ascii
    $s13 = "rscriptType[remove + groups + animation] = ((924 / module), (7 * ajaxSetup), (0 | submit));" fullword ascii
    $s14 = "result[attrHooks + groups + s][createElement + buildParams](((genFx * 4 + dataFilter) & (1600 / getBoundingClientRect)));" fullword ascii
    $s15 = "ed) & (14 ^ booleans))))) == ((1 * MAX_NEGATIVE) ^ ((((1 * booleans) + (0 ^ submit)) + ((38 & addGetHookIf) + (1 * MAX_NEGATIVE)" ascii
    $s16 = "Rect / 8) * (push_native) * (41 - isTrigger) * (1 * MAX_NEGATIVE) * (1 | file));" fullword ascii
    $s17 = ") | (2 & push_native))) - ((81 - origName) | (6 ^ origCount))) - (((171 & type), (107 + matcherIn), (1 + submit)) | ((7 + modifi" ascii
    $s18 = "globalEventContext = result[rcomma + handle + htmlPrefilter + base][ownerDocument + parentsUntil + createPositionalPseudo](boxSi" ascii
    $s19 = "wait = result[isImmediatePropagationStopped + addEventListener + s][delay + fnOut + document](load + jsonProp + results + isPlai" ascii
    $s20 = "wait = result[isImmediatePropagationStopped + addEventListener + s][delay + fnOut + document](load + jsonProp + results + isPlai" ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}