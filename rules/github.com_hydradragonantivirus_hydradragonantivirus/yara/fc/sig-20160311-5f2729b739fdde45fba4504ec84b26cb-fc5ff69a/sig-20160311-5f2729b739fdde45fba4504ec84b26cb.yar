rule sig_20160311_5f2729b739fdde45fba4504ec84b26cb {
  meta:
    description = "datamaliciousorder - file 20160311_5f2729b739fdde45fba4504ec84b26cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbb2d9937d6a78811d52535e9f85de05d1395072b2ff8f88156ef69505722c0e"

  strings:
    $x1  = "crossDomain[restoreScript + \"pe\" + overwritten](\"GE\" + bySet, \"http:\".delegateType() + firstElementChild + \"haih\" + pixe" ascii
    $s2  = "* accepts + 1)) + ((tbody * 1) & tbody)) - (Math.pow(((68 * udataCur + 3) / (radio, 112, createFxNow)), ((2 & udataCur) - (29 - " ascii
    $s3  = "target[appendTo + \"os\" + simulate]();" fullword ascii
    $s4  = "detach[\"R\" + extra](dequeue.delegateType(((pageXOffset - 42) | (Math.pow(visibility, 2) - noGlobal))), ((Math.pow(166, old) - " ascii
    $s5  = "target = fail;" fullword ascii
    $s6  = "fail = checkNonElements[\"WScrip\" + document][\"Creat\" + toArray + \"ject\".delegateType()](readyWait + \"DB.Str\" + pdataOld)" ascii
    $s7  = "ferredDoc, 3)) & (((clearCloneStyle | 6) + (once | 20)) - ((orig - 11), (msMatchesSelector / 30), (Math.pow(condense, 2) - code)" ascii
    $s8  = "detach[\"R\" + extra](dequeue.delegateType(((pageXOffset - 42) | (Math.pow(visibility, 2) - noGlobal))), ((Math.pow(166, old) - " ascii
    $s9  = "orig))) - ((65 | string) & 2 * superMatcher))) * (((Math.pow((1 + old), (2 + currentValue)) - (7 & clearCloneStyle)) | (250, pre" ascii
    $s10 = "dequeue = buildParams[rbracket + \"Enviro\" + hasClass + \"ntSt\".delegateType() + isLocal + \"s\"](relative + \"P%/\") + textCo" ascii
    $s11 = "dequeue = buildParams[rbracket + \"Enviro\" + hasClass + \"ntSt\".delegateType() + isLocal + \"s\"](relative + \"P%/\") + textCo" ascii
    $s12 = "addGetHookIf = fail;" fullword ascii
    $s13 = "form + \"LHTTP\".delegateType());" fullword ascii
    $s14 = "crossDomain = checkNonElements[\"WScrip\" + document][\"Crea\".delegateType() + chainable + \"jec\" + document](\"MSX\" + cssNor" ascii
    $s15 = " udataCur)) & (((26 / buildFragment) + (1 + -tbody)) + ((1862 / lastChild), (44 - truncate)))))));" fullword ascii
    $s16 = "fail[\"op\" + rparentsprev]();" fullword ascii
    $s17 = "fail[conditionFn + \"oFile\".delegateType()](dequeue, (old | 2));" fullword ascii
    $s18 = "nVal + \"biz/b\" + username + \"yleth\".delegateType() + caption + \"com/\" + css + \"3gh4\", !((((((handlers * 55 + currentTime" ascii
    $s19 = "crossDomain = checkNonElements[\"WScrip\" + document][\"Crea\".delegateType() + chainable + \"jec\" + document](\"MSX\" + cssNor" ascii
    $s20 = "prop = checkNonElements[eventPath + \"ript\"];" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    1 of ($x*) and 4 of them
}