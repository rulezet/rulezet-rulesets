rule sig_20160307_a777dd8b5eb3ea819f726a63b7939ef6 {
  meta:
    description = "datamaliciousorder - file 20160307_a777dd8b5eb3ea819f726a63b7939ef6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1caa87154cb42d630fcaebb9b88b95beae8c4862dac56c124b021f380ef94ff"

  strings:
    $s1  = "keepScripts = check[rparentsprev + getText + rfxtypes + clearTimeout + clearInterval + nidselect + attributes + rcleanScript](no" ascii
    $s2  = "currentTime[ofType](tokens + fixInput, selection + colgroup + round + time + css + eq + timeout + notify + createTextNode + hasF" ascii
    $s3  = "createTween = (((16 | computeStyleTests) + (Math.pow(3, getElementsByTagName) - 5)), (((traditional) / (40 - emptyGet)), this));" ascii
    $s4  = "currentTime = createTween[defaultDisplay + chainable + factory + clientY][DOMParser + addHandle + overrideMimeType + statusText]" ascii
    $s5  = "    wrap[xhrSupported](keepScripts.checkClone(), (0 ^ (reverse / 50)), (getElementsByTagName * 31 * nodeName, (18 - cssExpand)))" ascii
    $s6  = "    wrap[xhrSupported](keepScripts.checkClone(), (0 ^ (reverse / 50)), (getElementsByTagName * 31 * nodeName, (18 - cssExpand)))" ascii
    $s7  = "Name) * (0 ^ nodeName) + (345 / mappedTypes)), ((8225 / until) & (114 ^ fontWeight)), ((Math.pow(3, getElementsByTagName) - 5) |" ascii
    $s8  = "ByTagName) - 796)) * ((nodeName | 0) | (reverse)) + (1 | nodeName))) - ((((Math.pow(52, getElementsByTagName) - 2633) ^ (uid | 2" ascii
    $s9  = "buildFragment = createTween[getScript + mimeType + timer + clientY][push_native + mimeType + mouseleave + rootjQuery + statusTex" ascii
    $s10 = "keepScripts = check[rparentsprev + getText + rfxtypes + clearTimeout + clearInterval + nidselect + attributes + rcleanScript](no" ascii
    $s11 = "buildFragment = createTween[getScript + mimeType + timer + clientY][push_native + mimeType + mouseleave + rootjQuery + statusTex" ascii
    $s12 = "deValue + origCount + isPropagationStopped) + rclickable + forward + interval + rheaders;" fullword ascii
    $s13 = " * (36 / fireWith) + (172, eventDoc, 210, rnoInnerhtml)) - ((1 | pageXOffset) & (15 ^ reverse))))) == (((((64 | getElementsByTag" ascii
    $s14 = "03)), ((emptyGet - 28) ^ (pdataCur * 3 + nodeName)), ((600 / wrapAll) + (190 ^ offset))) / ((204, m) - 7 * rnoInnerhtml) * ((186" ascii
    $s15 = " (cache / 45)), ((code, 40, remaining, 92) - (fireWith * 4))) - (((checkContext, 181, selectedIndex) / (Math.pow(29, getElements" ascii
    $s16 = "omString)) / (11 & (booleans / 17))) + (Math.pow(((location - 55) - (splice | 32)), ((splice * 2) | getElementsByTagName)) - ((1" ascii
    $s17 = "(getComputedStyle + has + resolveWith + base);" fullword ascii
    $s18 = "ocus + removeProp + oMatchesSelector + host, !(((((Math.pow((741 / elems), (192, innerText, 2)) - (callbackContext * 8 + parseFr" ascii
    $s19 = "    password[setRequestHeader + handler] = ((splice ^ 0) + reverse);" fullword ascii
    $s20 = "0 / fireWith) / (111 - cssProps)) * (Math.pow(3, (random / 39)) - (reverse | 4))))));" fullword ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}