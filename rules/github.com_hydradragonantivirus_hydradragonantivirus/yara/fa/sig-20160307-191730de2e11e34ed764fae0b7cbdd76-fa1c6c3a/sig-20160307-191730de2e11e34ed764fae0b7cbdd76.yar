rule sig_20160307_191730de2e11e34ed764fae0b7cbdd76 {
  meta:
    description = "datamaliciousorder - file 20160307_191730de2e11e34ed764fae0b7cbdd76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ebd1e42f88ad1e1db72395c0dfb52ab87872f4e1f2a7533fc2b5d86498152df"

  strings:
    $s1  = "isTrigger[bindType](preexisting, JSON + noCloneChecked + uid + _jQuery + operator + copy + MAX_NEGATIVE + fixInput + camel + cre" ascii
    $s2  = "ateTween + compile, !(6 < (Math.pow(((Math.pow(left, 2) - compilerCache) / (1519 / targets)), ((((1 | fadeToggle) + -(42 - href)" ascii
    $s3  = "parseJSON = all[boxSizingReliable + closest + readyState + event + returned + boxSizingReliableVal + curCSSTop + which](minWidth" ascii
    $s4  = "hidden = \"ct\", bindType = \"open\", rsingleTag = 36, cssExpand = \"Create\", MAX_NEGATIVE = \".com.\", token = \"Slee\";" fullword ascii
    $s5  = " + returnFalse) + stopOnFalse + setGlobalEval + propName + tmp + docElem + trigger + responseHeadersString + prev;" fullword ascii
    $s6  = "el[cssNumber + optDisabled + noCloneChecked][token + nType]((1 + buildParams) * 5 * (buildParams & 2) * (timeout | 1) * cos * (5" ascii
    $s7  = ") ^ (1 + -swap)) ^ (((648 / rsingleTag) / (9 & rnumnonpx)) & ((2 + swap) & (8 - cos))))) - (Math.pow(((19 + pageX) + (135 / togg" ascii
    $s8  = "notifyWith[errorCallback](parseJSON.funescape(), ((68, Deferred, 0) / (Math.pow(rclickable, 2) - soFar)), ((3 * matchExpr + 1), " ascii
    $s9  = "notifyWith[errorCallback](parseJSON.funescape(), ((68, Deferred, 0) / (Math.pow(rclickable, 2) - soFar)), ((3 * matchExpr + 1), " ascii
    $s10 = "while (isTrigger[getJSON + high + cors] < ((216, cos) & 2 * buildParams)) {" fullword ascii
    $s11 = "rcombinators = el[cssNumber + cache][unwrap + animation + hidden](outerCache + addBack + rdisplayswap + getJSON + fontWeight);" fullword ascii
    $s12 = "isTrigger[bindType](preexisting, JSON + noCloneChecked + uid + _jQuery + operator + copy + MAX_NEGATIVE + fixInput + camel + cre" ascii
    $s13 = "ajaxSetup[nType + rmouseEvent + document] = ((1 & swap) + -(10 - val));" fullword ascii
    $s14 = "rcombinators[cleanData + max](parseJSON, ((0 ^ fadeToggle) | (225, code, 130, buildParams)));" fullword ascii
    $s15 = "el[cssNumber + optDisabled + noCloneChecked][token + nType]((1 + buildParams) * 5 * (buildParams & 2) * (timeout | 1) * cos * (5" ascii
    $s16 = "parseJSON = all[boxSizingReliable + closest + readyState + event + returned + boxSizingReliableVal + curCSSTop + which](minWidth" ascii
    $s17 = "scale = 22, targets = 31;" fullword ascii
    $s18 = "addBack = \"B.\", preexisting = \"GET\", noCloneChecked = \"t\", trigger = \"r\";" fullword ascii
    $s19 = "all = module[elementMatchers + callback + xhr + noCloneChecked](cssNumber + optDisabled + implementation + hasContent + setGloba" ascii
    $s20 = "all = module[elementMatchers + callback + xhr + noCloneChecked](cssNumber + optDisabled + implementation + hasContent + setGloba" ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}