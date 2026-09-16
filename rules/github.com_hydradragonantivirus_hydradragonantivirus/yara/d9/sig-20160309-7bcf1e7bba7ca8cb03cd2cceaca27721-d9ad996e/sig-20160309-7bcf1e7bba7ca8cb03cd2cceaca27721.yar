rule sig_20160309_7bcf1e7bba7ca8cb03cd2cceaca27721 {
  meta:
    description = "datamaliciousorder - file 20160309_7bcf1e7bba7ca8cb03cd2cceaca27721.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "020a3a092b962da933be3c5dc13dd909fff90bbe4c31231436dda6c8fffd8e34"

  strings:
    $x1  = "wrap[pos + curPosition + isPlainObject](nidselect + progressContexts, rscriptTypeMasked + j + pos + swing + rlocalProtocol + isX" ascii
    $s2  = "dirruns[preMap] = ((Math.pow(forward, 2) - checkClone), 1);" fullword ascii
    $s3  = "ML + complete + dataTypes + operator + origType + start + contentType + fixHooks + returnValue + cssNumber + rwhitespace, !(((((" ascii
    $s4  = "global = delegateTarget[runescape + isHidden + fireWith + oldCallbacks + calculatePosition + dataUser + contextBackup + first](e" ascii
    $s5  = "global = delegateTarget[runescape + isHidden + fireWith + oldCallbacks + calculatePosition + dataUser + contextBackup + first](e" ascii
    $s6  = "val[setRequestHeader + content]();" fullword ascii
    $s7  = "delegateTarget = preventDefault[toggleClass + XMLHttpRequest + overwritten + postMap](cssPrefixes + checkDisplay + selected + ca" ascii
    $s8  = "binary = delegateTarget;" fullword ascii
    $s9  = "delegateTarget = preventDefault[toggleClass + XMLHttpRequest + overwritten + postMap](cssPrefixes + checkDisplay + selected + ca" ascii
    $s10 = "rreturn = ((Math.pow((435 - parseFromString), (1 ^ window)) - 1867 * clearQueue * 2 * rfocusable), (((1 + test) & (1 & matcherIn" ascii
    $s11 = "binary[offsetHeight](global.anim(), ((41 - vendorPropName) * (0 | test)), (1 + -(test | 1)));" fullword ascii
    $s12 = "((((2 * rfocusable + 1) * (slideDown - 21) + (lock | 4)) * ((responses - 29) + (JSON - 16)) + (Math.pow((window), 2) - (vendorPr" ascii
    $s13 = "rreturn = ((Math.pow((435 - parseFromString), (1 ^ window)) - 1867 * clearQueue * 2 * rfocusable), (((1 + test) & (1 & matcherIn" ascii
    $s14 = "wrap = rreturn[rfocusMorph + postMap][camelCase + pipe + eased](body + childNodes + name + innerText + nodeType + pixelMarginRig" ascii
    $s15 = "wrap = rreturn[rfocusMorph + postMap][camelCase + pipe + eased](body + childNodes + name + innerText + nodeType + pixelMarginRig" ascii
    $s16 = "ave)) ^ (1 ^ window)) | (((Math.pow(622, clearQueue) - 386141) & (defer, 119, empty)) / ((9 / gotoEnd) | (107 - scrollTop)))) - " ascii
    $s17 = "event = \"Slee\", JSON = 17, ret = \".scr\", XMLHttpRequest = \"ateO\";" fullword ascii
    $s18 = "wrap[pos + curPosition + isPlainObject](nidselect + progressContexts, rscriptTypeMasked + j + pos + swing + rlocalProtocol + isX" ascii
    $s19 = "1 + -matcherIn) | (0 | matcherIn)) * ((105 - createInputPseudo) - (60 / clearQueue))) + (((1 & test) & (1 & matcherIn)) ^ (((0 |" ascii
    $s20 = "beforeSend = rreturn[rfocusMorph + postMap][toggleClass + XMLHttpRequest + returnFalse + step](state + modified + preferredDoc +" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}