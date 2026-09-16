rule sig_20160308_633d1223df9b129993ba680106a8649f {
  meta:
    description = "datamaliciousorder - file 20160308_633d1223df9b129993ba680106a8649f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b42846a40c61390557c7ad83204d3840d984ac2b42ff7e42bb18584ae2089bb8"

  strings:
    $s1  = "emptyStyle[select](swap + end, stopOnFalse + selectors + rcomma + rmargin + tfoot + ajaxTransport + processData + write, !(10 ==" ascii
    $s2  = "emptyStyle[select](swap + end, stopOnFalse + selectors + rcomma + rmargin + tfoot + ajaxTransport + processData + write, !(10 ==" ascii
    $s3  = "readyList[doneName](prev.animated(), ((107, unique) / (5 + nodeValue)), (1 * (getWidthOrHeight + -1)));" fullword ascii
    $s4  = " ((((response, 1) | ((indirect - 78) / (stateString + 14))) + (((getWidthOrHeight * 1) + (getWidthOrHeight * 0)) ^ (getWidthOrHe" ascii
    $s5  = "ight + -1))), ((((nodeValue * 3 + which) ^ (311 & unit)) & ((8143 & getElementsByClassName) / (Math.pow(10, head) - 82))) / (((f" ascii
    $s6  = "while(emptyStyle[thead + matched + detach + oldCallbacks] < ((isArrayLike ^ 163), nodeValue * 2, (top * 2 + rcleanScript), (2 ^ " ascii
    $s7  = "while(emptyStyle[thead + matched + detach + oldCallbacks] < ((isArrayLike ^ 163), nodeValue * 2, (top * 2 + rcleanScript), (2 ^ " ascii
    $s8  = "oMatchesSelector[selection] = ((getWidthOrHeight | 1) * (getWidthOrHeight * 1));" fullword ascii
    $s9  = "  one[lastChild + b][getAttributeNode + oldCallbacks + send]((47 + (holdReady, 149, docElem, 53)));" fullword ascii
    $s10 = "one = (((888 / camelKey) ^ (0 / marginLeft)), (((1 * unique) | (0 ^ getWidthOrHeight)), this));" fullword ascii
    $s11 = "opacity[destElements](emptyStyle[addCombinator + pixelPositionVal + hookFn]);" fullword ascii
    $s12 = "implementation = mimeType[clearInterval + curCSSTop + binary](lastChild + submit + parent);" fullword ascii
    $s13 = "  ifModified = \"TEMP%\"," fullword ascii
    $s14 = "opacity = one[unshift + showHide + fnOut + b][lname + originAnchor + createFxNow + isDefaultPrevented + setMatcher](transports +" ascii
    $s15 = "prev = implementation[nodes + rheaders + matchExpr + onabort + now + visible + conv + fx](callbackExpect + ifModified + reverse)" ascii
    $s16 = "head = 2;" fullword ascii
    $s17 = "prev = implementation[nodes + rheaders + matchExpr + onabort + now + visible + conv + fx](callbackExpect + ifModified + reverse)" ascii
    $s18 = "mimeType = one[adown + empty + eased];" fullword ascii
    $s19 = "opacity[dir + filter + oldCallbacks](prev, (44 - checkbox));" fullword ascii
    $s20 = "preDispatch = \".Str\";" fullword ascii

  condition:
    uint16(0) == 0x6970 and
    8 of them
}