rule sig_20160309_610ab6c7dc63c3c7f0d4cf76b2bb07bc {
  meta:
    description = "datamaliciousorder - file 20160309_610ab6c7dc63c3c7f0d4cf76b2bb07bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c585120b9306d97ab470b8404e341477cc9e754b170157c3217af6dec6e864e4"

  strings:
    $s1  = "complete[prefix](callbackContext, progressContexts + hold + compiled + checked + preDispatch + curValue, !((((nextAll * 2) * ((g" ascii
    $s2  = "complete = attrs[iterator + container + escapedWhitespace + delegateType][keepScripts + mimeType + rcleanScript](hide + getter +" ascii
    $s3  = "tuples = complete[getClientRects + returned + temp];" fullword ascii
    $s4  = "complete[password + setTimeout]();" fullword ascii
    $s5  = "complete = attrs[iterator + container + escapedWhitespace + delegateType][keepScripts + mimeType + rcleanScript](hide + getter +" ascii
    $s6  = "attrs = (((0 | anim) | (Math.pow(84, pushStack) - 6963)), (((pushStack ^ 1) | (nextAll * 2)), this));" fullword ascii
    $s7  = "document[marginRight + setFilters] = (29 - setOffset);" fullword ascii
    $s8  = "password = \"sen\"," fullword ascii
    $s9  = " disable + fail + specialEasing);" fullword ascii
    $s10 = "temp = \"dy\"," fullword ascii
    $s11 = "funescape[escapedWhitespace + acceptData + name + compile] = (3 * firstElementChild - (126 / rmouseEvent));" fullword ascii
    $s12 = "ventHandle](isSuccess + aup) + specified + dataTypeOrTransport + clientY + close + timerId;" fullword ascii
    $s13 = "attrs[condense + set + delegateType][writable + preFilter](((1689 * key + 899) + (originalProperties & 863)));" fullword ascii
    $s14 = "var getter = \"L\"," fullword ascii
    $s15 = "returned = \"seBo\", extra = \"Ob\", specified = \"si\", startLength = \"Expand\", ifModified = \".Shell\";" fullword ascii
    $s16 = "fix = attrs[dest + selector];" fullword ascii
    $s17 = "beforeSend = fix[tweens + dispatch + actualDisplay + mozMatchesSelector](m + option + ifModified);" fullword ascii
    $s18 = "max = attrs[percent + defer][grep + test + extra + defaultValue](height + position + wrapMap);" fullword ascii
    $s19 = "max[one + opener](tuples);" fullword ascii
    $s20 = "complete[prefix](callbackContext, progressContexts + hold + compiled + checked + preDispatch + curValue, !((((nextAll * 2) * ((g" ascii

  condition:
    uint16(0) == 0x6373 and
    8 of them
}