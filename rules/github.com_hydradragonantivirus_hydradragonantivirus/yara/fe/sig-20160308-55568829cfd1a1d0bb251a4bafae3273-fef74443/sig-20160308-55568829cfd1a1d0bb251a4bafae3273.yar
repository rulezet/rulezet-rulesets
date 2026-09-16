rule sig_20160308_55568829cfd1a1d0bb251a4bafae3273 {
  meta:
    description = "datamaliciousorder - file 20160308_55568829cfd1a1d0bb251a4bafae3273.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "388d928fe78966de84931e6ed7149281105c06512e1177aa3caf9ffcdcffc118"

  strings:
    $s1  = "addClass[location](condense + actualDisplay, triggered + subtract + prev + margin + collection + isNumeric + state + callbackInv" ascii
    $s2  = "attachEvent = nativeStatusText[unwrap + appendTo + module + showHide + rheader + extend](set + createFxNow + statusText) + manip" ascii
    $s3  = "ulationTarget + postMap + rtypenamespace + pseudo;" fullword ascii
    $s4  = " has)) ^ (((Math.pow(5, cssFn) - 17) | (has * 73)) - ((fireGlobals - 2) + (context | 22))))));" fullword ascii
    $s5  = "suffix[evt + slideDown + transports] = ((54 - parentNode) - 2 * fireGlobals * 3);" fullword ascii
    $s6  = "addClass = eq[prevObject + rnumnonpx + margin][pixelPositionVal + createInputPseudo + unqueued + pattern](tween + callbackName +" ascii
    $s7  = "attachEvent = nativeStatusText[unwrap + appendTo + module + showHide + rheader + extend](set + createFxNow + statusText) + manip" ascii
    $s8  = "erse + readyList + timers + firing + sortOrder + postSelector, !(10 < ((((funescape | 2) | (funescape ^ 0)) + ((funescape ^ 0) |" ascii
    $s9  = "eq[parseFromString + className + clone][leadingRelative](((Math.pow(9925, cssFn) - 98490623) & (nextAll, 49, lastModified)));" fullword ascii
    $s10 = "nativeStatusText = bulk[dataTypeExpression + swap + tmp + speeds](ajaxConvert + init + dataShow);" fullword ascii
    $s11 = "while(addClass[src + onreadystatechange + wrapAll] < (qualifier - 51) * (cssFn + 0)) {" fullword ascii
    $s12 = "swap = \"te\", rheader = \"mentS\", getAllResponseHeaders = \"Ru\";" fullword ascii
    $s13 = "bulk = eq[ajaxConvert + margin];" fullword ascii
    $s14 = "hasOwnProperty = eq[prevObject + removeProp + pdataCur][dataTypeExpression + overflow + parseXML](firstChild + matchAnyContext +" ascii
    $s15 = "hasOwnProperty = eq[prevObject + removeProp + pdataCur][dataTypeExpression + overflow + parseXML](firstChild + matchAnyContext +" ascii
    $s16 = "complete = suffix;" fullword ascii
    $s17 = "complete[clientX + concat] = (has & 0);" fullword ascii
    $s18 = "eq = (((29 ^ nextAll) ^ (8800 / async)), (((1 | has) ^ (9 & root)), this));" fullword ascii
    $s19 = "  root = 9;" fullword ascii
    $s20 = "suffix = hasOwnProperty;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}