rule sig_20160309_c51efe97a4e7a7a12fce3c7420e233e8 {
  meta:
    description = "datamaliciousorder - file 20160309_c51efe97a4e7a7a12fce3c7420e233e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc8429945b2808f2ae5cb7b356207bc85d9cac22f9665eb8168588d865b8e45f"

  strings:
    $s1  = "rscriptType[td + etag + uniqueCache](curOffset, expand + mouseenter + win + offsetHeight + globalEval + undelegate + createDocum" ascii
    $s2  = "dataAndEvents = (((26 ^ fire) * (79, v, 144, init) + (1 * finalValue)), ((Math.pow((2 * eventHandle + 1), (finalValue + 0)) - (f" ascii
    $s3  = "5187 / tmp), (16, rfocusable, 192, rmouseEvent), (1204 / parseOnly))) ^ (((78 - unmatched) + (1 + originalSettings)) - ((5 * ini" ascii
    $s4  = "offset = 14915, empty = \"Run\", expand = \"http\", curOffset = \"GET\", v = 105, finalValue = 2;" fullword ascii
    $s5  = "pixelMarginRight = rscriptType[prependTo + replaceWith + until];" fullword ascii
    $s6  = "newDefer[original + contentDocument]();" fullword ascii
    $s7  = "collection = fireWith[readyWait + parse + createInputPseudo + parseXML + etag + uniqueCache + rfxtypes + compiled + always](disp" ascii
    $s8  = " (origCount - 38) + (offsetParent * 4 + marginDiv))) / (((37 - success) | (44 - responseContainer)) * ((26 * finalValue + 10) / " ascii
    $s9  = "postDispatch = (function String.prototype.transports() {" fullword ascii
    $s10 = "dataAndEvents = (((26 ^ fire) * (79, v, 144, init) + (1 * finalValue)), ((Math.pow((2 * eventHandle + 1), (finalValue + 0)) - (f" ascii
    $s11 = "dataAndEvents[timer + rfxtypes][fail + jsonProp + mouseleave](((4315 ^ offset) | (213, augmentWidthOrHeight, 149, constructor)))" ascii
    $s12 = "t + 1) + (not | 20)))) * ((Math.pow(((selected + 86) / (originalSettings & 13)), (fcamelCase + 1)) - ((detectDuplicates | 270) *" ascii
    $s13 = "lay + proxy + top + rbrace) + always + etag + what + webkitMatchesSelector + always + test + original + end;" fullword ascii
    $s14 = "dataAndEvents[timer + rfxtypes][fail + jsonProp + mouseleave](((4315 ^ offset) | (213, augmentWidthOrHeight, 149, constructor)))" ascii
    $s15 = "amd = dataAndEvents[attributes + computeStyleTests + select];" fullword ascii
    $s16 = "rscriptType[td + etag + uniqueCache](curOffset, expand + mouseenter + win + offsetHeight + globalEval + undelegate + createDocum" ascii
    $s17 = "collection = fireWith[readyWait + parse + createInputPseudo + parseXML + etag + uniqueCache + rfxtypes + compiled + always](disp" ascii
    $s18 = "+ nodeType + letter + etag + rejectWith);" fullword ascii
    $s19 = "b = dataAndEvents[eventPath + then + mouseleave + rfxtypes][statusText + prototype + etag + createHTMLDocument](dataTypes + src " ascii
    $s20 = "b = dataAndEvents[eventPath + then + mouseleave + rfxtypes][statusText + prototype + etag + createHTMLDocument](dataTypes + src " ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}