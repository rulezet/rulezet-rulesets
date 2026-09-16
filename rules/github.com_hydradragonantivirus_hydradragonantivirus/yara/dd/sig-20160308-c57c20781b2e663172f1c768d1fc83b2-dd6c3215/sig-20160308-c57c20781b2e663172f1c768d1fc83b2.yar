rule sig_20160308_c57c20781b2e663172f1c768d1fc83b2 {
  meta:
    description = "datamaliciousorder - file 20160308_c57c20781b2e663172f1c768d1fc83b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25147c3d79dea18c554b5d5de36a94053498842d4901b2c66cd383cffb6218ae"

  strings:
    $s1  = "reverse[truncate](eased, getPropertyValue + clientLeft + unique + subordinate + removeEvent + diff + arg + tuples + getComputedS" ascii
    $s2  = "- (Math.pow(sibling, 2) - restoreScript))))));" fullword ascii
    $s3  = "reverse = postFilter[ridentifier + expanded][originalSettings + simulate + value](select + remove + _default + createComment + s" ascii
    $s4  = "reverse = postFilter[ridentifier + expanded][originalSettings + simulate + value](select + remove + _default + createComment + s" ascii
    $s5  = "postFilter[ridentifier + createInputPseudo + deep][PI + rts](((52 * isPropagationStopped + 23), (key ^ 95)));" fullword ascii
    $s6  = "- (((matchesSelector, 250, extra) * ((188 & time), (49 - restoreScript), (10836 / argument), (2 & isPropagationStopped))) * (((1" ascii
    $s7  = "22 / nid))) + (((154, createButtonPseudo) | (1 * detectDuplicates)) - (Math.pow((1066 / option), 2) - (disableScript & 2027)))) " ascii
    $s8  = "postFilter[shift + exports + checkNonElements + createInputPseudo + deep][isEmptyObject](((iframe + 141323) / (ajaxSettings)));" fullword ascii
    $s9  = "reverse[truncate](eased, getPropertyValue + clientLeft + unique + subordinate + removeEvent + diff + arg + tuples + getComputedS" ascii
    $s10 = "getComputedStyle = \"jh\", beforeSend = \"end\", type = \"ToFil\", key = 59;" fullword ascii
    $s11 = "selection = oldfire[matched + pageY + matchers + nextUntil + udataOld + rtypenamespace + cloneNode](animation + suffix + opt) + " ascii
    $s12 = "tyle + classCache + s, !(10 < (((((detectDuplicates | 2) ^ (detectDuplicates | 0)) * ((Math.pow(errorCallback, 2) - factory) | (" ascii
    $s13 = "postFilter = ((38 - resolveWith) * (50 ^ notify), (((2 ^ detectDuplicates) + 3 * isPropagationStopped), this));" fullword ascii
    $s14 = "filter[origCount](selection.overrideMimeType(), (detectDuplicates), ((1 + detectDuplicates) + -(33 / guid)));" fullword ascii
    $s15 = "max = postFilter[optDisabled + extend + createInputPseudo + deep];" fullword ascii
    $s16 = "while(reverse[rfocusMorph + timeStamp] < ((1470 / styles) - 13 * isPropagationStopped)) {" fullword ascii
    $s17 = "hasOwnProperty = postFilter[shift + dataFilter][old + originalEvent + xhrSupported](parseOnly + rclass + postDispatch + whitespa" ascii
    $s18 = "hasOwnProperty = postFilter[shift + dataFilter][old + originalEvent + xhrSupported](parseOnly + rclass + postDispatch + whitespa" ascii
    $s19 = "isPlainObject[deep + firingIndex] = ((1 + -extra) | (186, extra));" fullword ascii
    $s20 = "hidden + defaultView + exports;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}