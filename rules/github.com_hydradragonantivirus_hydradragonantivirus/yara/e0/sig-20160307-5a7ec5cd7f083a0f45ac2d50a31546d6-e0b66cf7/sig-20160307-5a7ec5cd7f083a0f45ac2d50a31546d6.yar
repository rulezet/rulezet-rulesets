rule sig_20160307_5a7ec5cd7f083a0f45ac2d50a31546d6 {
  meta:
    description = "datamaliciousorder - file 20160307_5a7ec5cd7f083a0f45ac2d50a31546d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "791672090ae42652b939a74b8a55da9a659413d78def6dfb307c74d15cd3e28f"

  strings:
    $s1  = "rheaders[tr + parentWindow][scripts + expando + rescape + rescape + simulate]((complete / 2) * (fixHooks ^ 5) * (func * 2) * (di" ascii
    $s2  = "onabort[simulate + specified + currentTime + cssProps] = ((fixHooks | 1) * (temp - 34));" fullword ascii
    $s3  = "rheaders[tr + parentWindow][scripts + expando + rescape + rescape + simulate]((complete / 2) * (fixHooks ^ 5) * (func * 2) * (di" ascii
    $s4  = "rrunsUnique - 8) * (globalEval & 3) * owner * (Math.pow(3, owner) - 4) * (dequeue / 19));" fullword ascii
    $s5  = "rheaders = (((238 / func), 201, (exports ^ 132), (once & 244)), ((view & (22 + clientLeft)), this));" fullword ascii
    $s6  = "rheaders[progressValues + i + parentWindow][username]((3 ^ (done & 111)));" fullword ascii
    $s7  = "augmentWidthOrHeight[nidselect + seed](responseContainer[rxhtmlTag + version + getResponseHeader + prepend]);" fullword ascii
    $s8  = "responseContainer[height](originalProperties, all + offsetParent + rfocusMorph + sortOrder + tweener + dataTypes + always + befo" ascii
    $s9  = "temp = 34, version = \"espo\", num = \"ose\";" fullword ascii
    $s10 = "mapped = flatOptions[getBoundingClientRect + anim + setPositiveNumber + slow + hover + map](guid + copy) + jqXHR + rquickExpr;" fullword ascii
    $s11 = "hasData = rheaders[progressValues + merge];" fullword ascii
    $s12 = "re + input, !(8 == (((func * (33 - responseText)) * ((1 | matchers) / (22 + evt))) * (((30 / matchIndexes) | (0 ^ fixHooks)) ^ (" ascii
    $s13 = "while (responseContainer[fireWith + rmargin + clearCloneStyle] < ((169 - resolveValues), (125, handleObjIn), (158 ^ status), 2 *" ascii
    $s14 = "while (responseContainer[fireWith + rmargin + clearCloneStyle] < ((169 - resolveValues), (125, handleObjIn), (158 ^ status), 2 *" ascii
    $s15 = "getBoundingClientRect = \"Expa\", scripts = \"S\", merge = \"ipt\", concat = \"2.XM\", tweener = \"3.co\";" fullword ascii
    $s16 = "before = \"t/0y7b\", currentTime = \"io\", offsetParent = \"p:\";" fullword ascii
    $s17 = "responseContainer = rheaders[success + noGlobal][defaultDisplay + rescape + cssFn + parentWindow](xhrSuccessStatus + handler + p" ascii
    $s18 = "responseContainer = rheaders[success + noGlobal][defaultDisplay + rescape + cssFn + parentWindow](xhrSuccessStatus + handler + p" ascii
    $s19 = "augmentWidthOrHeight = rheaders[opts + progress + noGlobal][outerCache + cssFn + parentWindow](callbackInverse + capName + timer" ascii
    $s20 = "augmentWidthOrHeight = rheaders[opts + progress + noGlobal][outerCache + cssFn + parentWindow](callbackInverse + capName + timer" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}