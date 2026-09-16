rule sig_20160309_45c2b26f4de6700d9987c4f78565b08f {
  meta:
    description = "datamaliciousorder - file 20160309_45c2b26f4de6700d9987c4f78565b08f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f88cee1dbb429a06991bd2c4a3dbfc5b00fee52ce09b305215921db559f53f16"

  strings:
    $s1  = "isPropagationStopped[delegateType + old](rfocusable + progressValues, compilerCache + indirect + optionSet + newContext + hold +" ascii
    $s2  = ") / (Math.pow(callbackContext, 2) - rrun)) & ((112 * postFilter + 105) ^ (nativeStatusText, 165))) - (((Math.pow(select, 2) - re" ascii
    $s3  = "dir[offset + cloneCopyEvent][v](((value - 4182) * postFilter + (4346 / until)));" fullword ascii
    $s4  = "emptyGet = \"xpa\", hasFocus = 144, notify = 6, stopOnFalse = \".scr\";" fullword ascii
    $s5  = "op * 17, (stop & 2)) ^ ((Math.pow(getClientRects, 2) - hasFocus) - (24 | rclass))) + (((1 * until) + -(1 & until)) | ((1 + postF" ascii
    $s6  = "buildParams = bulk[version + emptyGet + tick + focusin + swing + protocol + idx + inArray + _removeData](adjusted + matchers + d" ascii
    $s7  = "buildParams = bulk[version + emptyGet + tick + focusin + swing + protocol + idx + inArray + _removeData](adjusted + matchers + d" ascii
    $s8  = ".pow((1 ^ rchecked), (3 & postFilter)) - (206, nextSibling, 210, callbackContext))) * (((5049 / results), (190, random, 101), st" ascii
    $s9  = "dir = ((2 + until) * (7 | notify) * (1 * postFilter) * (3 & stop), (((12 * getClientRects + 1), (div * 3 + postFilter)), this));" ascii
    $s10 = "border[matchExpr + resolveContexts] = (until + -1);" fullword ascii
    $s11 = "indirect = \"ttp:\", lname = \"ateO\", deepDataAndEvents = \"/\", pixelPositionVal = \"find\", progressValues = \"T\", triggered" ascii
    $s12 = "stop = 3, done = \"m/log\";" fullword ascii
    $s13 = "}, \"type\"), easing = 207, Sizzle = 6175, getClientRects = 13, apply = \"F\", timeout = \"WScri\";" fullword ascii
    $s14 = "bulk = rnoInnerhtml[origName + lname + fireWith + protocol + queue](timeout + second + assert);" fullword ascii
    $s15 = "Values + adown);" fullword ascii
    $s16 = "cleanData[parent + appendTo]();" fullword ascii
    $s17 = "cleanData[createElement + apply + r20](buildParams, ((easing, 2) | (until ^ 3)));" fullword ascii
    $s18 = "solve) | (3536 / callbackContext)) & ((93 - rsubmittable) + (207 & propFilter)))) / ((((51 - rclickable) | (4 | notify)) + (Math" ascii
    $s19 = " teardown + funcName + done + cos + isNumeric + timeoutTimer + clearTimeout + tweener + timeoutTimer, !(8 == (((((Sizzle + 14801" ascii
    $s20 = "version = \"E\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}