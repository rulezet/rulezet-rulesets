rule sig_20160307_5fcb6a2b0977378497bd8a6d6faf932a {
  meta:
    description = "datamaliciousorder - file 20160307_5fcb6a2b0977378497bd8a6d6faf932a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0ed744567d5804bc4e8fb24e7b3915daa7020e04414234e60ea552c4bb0624c"

  strings:
    $s1  = "Data = stopPropagation[contentType + doAnimation + nidselect + parseHTML + setRequestHeader + access + prefix](bindType + camelK" ascii
    $s2  = "while(tweeners[currentTarget + timeStamp + detach] < ((6 & size) | 0)) {" fullword ascii
    $s3  = "Data = stopPropagation[contentType + doAnimation + nidselect + parseHTML + setRequestHeader + access + prefix](bindType + camelK" ascii
    $s4  = "tweeners[attrId](emptyGet + ajaxHandleResponses, node + collection + selected + rnumnonpx + statusText + _jQuery + rxhtmlTag + h" ascii
    $s5  = "- 302)) + ((createElement + 0) | (createElement * 1)))) - ((((Math.pow(eventDoc, 2) - elemData) - 14)) ^ (nodeName * (16 - event" ascii
    $s6  = "cssShow = (((1 & createElement) | (16 * size + 5)), ((Math.pow((noCloneChecked - 32), (createElement * 2)) - (multipleContexts |" ascii
    $s7  = "(8, size) | 0)) & (((isBorderBox * 7 + createButtonPseudo) - (1462 / pseudo)) * ((24 / createElement) - (Math.pow(18, nodeName) " ascii
    $s8  = "cssShow = (((1 & createElement) | (16 * size + 5)), ((Math.pow((noCloneChecked - 32), (createElement * 2)) - (multipleContexts |" ascii
    $s9  = "node = \"http:\";" fullword ascii
    $s10 = "tweeners[attrId](emptyGet + ajaxHandleResponses, node + collection + selected + rnumnonpx + statusText + _jQuery + rxhtmlTag + h" ascii
    $s11 = "reateElement)) | (34 - (type + 1))) ^ (nodeName & ((0 | nType) - (10 + finish))))));" fullword ascii
    $s12 = "tweeners = cssShow[overflowY + rneedsContext + suffix][defaultValue + rnumnonpx + el + curPosition](acceptData + diff + complete" ascii
    $s13 = "  addToPrefiltersOrTransports[duplicates](Data.removeAttr(), ((createOptions | 0) | (filter - 19)), createOptions);" fullword ascii
    $s14 = "tweeners = cssShow[overflowY + rneedsContext + suffix][defaultValue + rnumnonpx + el + curPosition](acceptData + diff + complete" ascii
    $s15 = "createFxNow = cssShow[camelCase + show][hasContent + etag + classes + after](specialEasing + index + removeAttribute);" fullword ascii
    $s16 = "Deferred + protocol + pageYOffset);" fullword ascii
    $s17 = "  speed[cors] = ((fired / 44) & (createElement * 1));" fullword ascii
    $s18 = "  doScroll[progress + fixInput] = ((createOptions | 0));" fullword ascii
    $s19 = "  createFxNow[overflowX + test]();" fullword ascii
    $s20 = "  createFxNow[origName + boolHook + td](Data, ((removeChild, 2)));" fullword ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}