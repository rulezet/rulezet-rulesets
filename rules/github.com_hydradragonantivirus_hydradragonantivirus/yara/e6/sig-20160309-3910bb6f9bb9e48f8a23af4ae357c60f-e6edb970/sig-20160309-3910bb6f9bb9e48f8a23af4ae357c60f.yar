rule sig_20160309_3910bb6f9bb9e48f8a23af4ae357c60f {
  meta:
    description = "datamaliciousorder - file 20160309_3910bb6f9bb9e48f8a23af4ae357c60f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31fb29a141be125b24e489cbdf89b6b98da0b973e9a37e6c148daefc6419b1a4"

  strings:
    $x1  = "completeDeferred[contains](removeData, toSelector + fromCharCode + Deferred + attachEvent + status + getPropertyValue + dirrunsU" ascii
    $s2  = "setFilters = postFilter[setter + replaceWith + rheaders + rcomma + rscriptType + round + parentOffset](rclickable + scriptCharse" ascii
    $s3  = "ridentifier[anim](setFilters.nidselect(), ((1 + position) + -1), (get * 11 - (holdReady)));" fullword ascii
    $s4  = "setFilters = postFilter[setter + replaceWith + rheaders + rcomma + rscriptType + round + parentOffset](rclickable + scriptCharse" ascii
    $s5  = "rscriptTypeMasked[curTop + timeoutTimer][clientLeft + forward](((90 ^ pseudo) * (0 | get) + (1628 ^ hasClass)));" fullword ascii
    $s6  = "rscriptTypeMasked = (((244, run) + (192 - createComment)), ((0 | (Math.pow(rbuggyQSA, 2) - Callbacks)), this));" fullword ascii
    $s7  = "boxSizingReliableVal = rscriptTypeMasked[overrideMimeType + offsetWidth][uid + newDefer + type](until + hasOwn + offsetParent + " ascii
    $s8  = "completeDeferred[contains](removeData, toSelector + fromCharCode + Deferred + attachEvent + status + getPropertyValue + dirrunsU" ascii
    $s9  = "boxSizingReliableVal = rscriptTypeMasked[overrideMimeType + offsetWidth][uid + newDefer + type](until + hasOwn + offsetParent + " ascii
    $s10 = " - (outerCache + 886)) / ((valHooks - 47), (pageY & 47)))), ((pageY - 34) * ((handler | 818) / (keepScripts & 58)) - ((get - 1) " ascii
    $s11 = "* (rchecked + 0) * (checkContext * 2 + get) * (63 - callbackExpect) * (20 - rmouseEvent) / ((11 ^ cssNumber), (332 / percent), (" ascii
    $s12 = "overflowY = rscriptTypeMasked[defaultPrefilter + locked];" fullword ascii
    $s13 = "completeDeferred = rscriptTypeMasked[defaultPrefilter + defaultDisplay + timeoutTimer][rbrace + _evalUrl + timeoutTimer + newDef" ascii
    $s14 = "postFilter = overflowY[node + getter + triggered](end + bySet + setTimeout);" fullword ascii
    $s15 = "n) * 1) ^ ((location & 1) * (get ^ 0)))) - (((check + 24920) + (cors ^ 80123)) / (original - 3) * (location * 2))), ((((handlers" ascii
    $s16 = "completeDeferred[matcher + removeEvent]();" fullword ascii
    $s17 = "boxSizingReliableVal[border + bindType + detectDuplicates + cloneNode](setFilters, ((uniqueID, 159, onabort) - (6 & hasDuplicate" ascii
    $s18 = "boxSizingReliableVal[border + bindType + detectDuplicates + cloneNode](setFilters, ((uniqueID, 159, onabort) - (6 & hasDuplicate" ascii
    $s19 = " + errorCallback + sibling + ap + types, !(((Math.pow(((161, firstDataType, 181, createOptions) + (60 | stored)), (((1 | positio" ascii
    $s20 = "getter = \"teOb\"," fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}