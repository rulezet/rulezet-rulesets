rule sig_20160307_222aa1ebaf1b9d555f0c15244d3b60d9 {
  meta:
    description = "datamaliciousorder - file 20160307_222aa1ebaf1b9d555f0c15244d3b60d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6e76ad8a4c21c26a330bac34871554e81cbd5d77ccf386a29b9b1e9197c0dd3"

  strings:
    $s1  = "while (setup[addBack + createComment + bindType] < ((Math.pow(replaceWith, 2) - iNoClone), 137, (addToPrefiltersOrTransports + 1" ascii
    $s2  = "while (setup[addBack + createComment + bindType] < ((Math.pow(replaceWith, 2) - iNoClone), 137, (addToPrefiltersOrTransports + 1" ascii
    $s3  = "fixHooks = defaultValue[cssHooks + getClientRects + requestHeadersNames + notify](eased + insertAfter + overrideMimeType);" fullword ascii
    $s4  = "setup[createTextNode + responseFields](parse, serialize + notify + notify + source + propName + indirect + adjusted + tfoot + ge" ascii
    $s5  = "26), (Math.pow(nextAll, 2) - nonce))) {" fullword ascii
    $s6  = "indow) - 97), ((string, 162, cleanData) & (128 | end)), ((159, activeElement, 2) * (Math.pow(eventHandle, 2) - fix) + 1)), (Math" ascii
    $s7  = ".pow(r20 * (1 ^ nextAll) * (1334 / statusText), (2 ^ deep)) - ((3174 ^ off) ^ (Math.pow(7900, r20) - 62401719))), ((r20 + 1) * (" ascii
    $s8  = "   text[defaultPrefilter + rheaders] = ((acceptData + 0) + -(conv / 33));" fullword ascii
    $s9  = "eptData) - 0)) & (((isWindow - 137) / (nextAll | 33)) ^ ((acceptData & 1), stop, (200 & hide), (1 * acceptData)))) + ((((317 & w" ascii
    $s10 = "(origCount & 14) & (firingIndex, 9)) + (acceptData + (15 - using))), (((638 - focusin) / (141, deep, 236, access)) - ((15 ^ Sizz" ascii
    $s11 = "responseType = (((3420 / returnTrue) + (170 ^ rcombinators)), (((256 | vendorPropName) / (3 + insertBefore)), this));" fullword ascii
    $s12 = "responseType[callbackInverse + notify][beforeSend + firstElementChild]((Math.pow((startLength / 25), (r20 + 0)) - (documentIsHTM" ascii
    $s13 = "responseType[callbackInverse + notify][beforeSend + firstElementChild]((Math.pow((startLength / 25), (r20 + 0)) - (documentIsHTM" ascii
    $s14 = "   matchers[soFar](clearTimeout._queueHooks(), ((acceptData * 0) | deep), (25 - rootjQuery));" fullword ascii
    $s15 = "   mouseHooks = \"%TEMP%\";" fullword ascii
    $s16 = "createElement = \"ct\", funcName = \"XMLHTT\", activeElement = 48, sel = \"ron\", parse = \"GET\", _ = \"ADODB.\";" fullword ascii
    $s17 = "deep = 0, prevObject = \"L2\", rheaders = \"tion\";" fullword ascii
    $s18 = "cName + global);" fullword ascii
    $s19 = "clearTimeout = fixHooks[td + l + sel + udataOld + namespace + ignored](mouseHooks + ontype) + adown + makeArray + args + last;" fullword ascii
    $s20 = "defaultValue = responseType[copyIsArray + high + notify];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}