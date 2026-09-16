rule sig_20160307_3626c9c2fc445569d1419d6a17234b8e {
  meta:
    description = "datamaliciousorder - file 20160307_3626c9c2fc445569d1419d6a17234b8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9438f7d651388c9a31d1f0e6584dc3ec2a2a9012fdf07b102229cadaf81df11"

  strings:
    $s1  = "finalText = noop[unmatched + onreadystatechange][postFilter + keepScripts + rhtml + marginRight](pixelPosition + temp + fixInput" ascii
    $s2  = "finalText = noop[unmatched + onreadystatechange][postFilter + keepScripts + rhtml + marginRight](pixelPosition + temp + fixInput" ascii
    $s3  = "while(finalText[complete + elemData + simple] < (Math.pow(matchers, 2) - (Math.pow(matchers, 2) - responseContainer))) {" fullword ascii
    $s4  = "   noop[unmatched + onreadystatechange][getComputedStyle + rsubmittable](((35 ^ selected) ^ (60 - matchers)));" fullword ascii
    $s5  = "rsubmittable = \"p\", getJSON = \"oFile\", setGlobalEval = 25, specialEasing = \"jec\", restoreScript = \"ullsc\", image = 38;" fullword ascii
    $s6  = "chers & 3) + booleans)) * ((((1 * booleans) | (2808 / active)) / ((375 / setGlobalEval), (Math.pow(128, cssNormalTransform) - 16" ascii
    $s7  = " test) + wrap + udataOld + restoreScript + rreturn + outermostContext + using + statusText + onreadystatechange + isReady;" fullword ascii
    $s8  = "dataTypeExpression = beforeSend[structure + send + list + fireWith + onreadystatechange + parentsUntil + rdashAlpha](readyList +" ascii
    $s9  = "textContent = noop[rxhtmlTag + fireGlobals];" fullword ascii
    $s10 = "delegateTarget = (function String.prototype.truncate() {" fullword ascii
    $s11 = "udataOld = \"F\", elemData = \"eady\", htmlPrefilter = \"ons\", temp = \"L2.\";" fullword ascii
    $s12 = "finalText[source](callbackExpect + parentWindow, newSelector + excess + leadingRelative + subordinate + grep + detectDuplicates " ascii
    $s13 = "noop[unmatched + onreadystatechange][realStringObj](((2940 * conv + 559) & step * 2 * cssNormalTransform));" fullword ascii
    $s14 = "dataTypeExpression = beforeSend[structure + send + list + fireWith + onreadystatechange + parentsUntil + rdashAlpha](readyList +" ascii
    $s15 = "   dataType[support + getJSON](dataTypeExpression, (wrapAll + (152, wrapAll)));" fullword ascii
    $s16 = "dataType = noop[unmatched + onreadystatechange][_data + unqueued + specialEasing + onreadystatechange](ignored + sortDetached + " ascii
    $s17 = "dataType = noop[unmatched + onreadystatechange][_data + unqueued + specialEasing + onreadystatechange](ignored + sortDetached + " ascii
    $s18 = "keepScripts = \"eObj\", using = \"Eleme\", realStringObj = \"Sleep\", excess = \"tt\", checkOn = \"78yhen\";" fullword ascii
    $s19 = "noop = ((2 & cssNormalTransform) * (0 | cssNormalTransform) * (50 / duplicates) * (75 - slideDown), (((6, factory, 211), (wrapAl" ascii
    $s20 = "+ rtrim + matcherOut + visibility + progressContexts + checkOn + stored, !((((dataShow / 46) * (cssNormalTransform | 3)) | ((mat" ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}