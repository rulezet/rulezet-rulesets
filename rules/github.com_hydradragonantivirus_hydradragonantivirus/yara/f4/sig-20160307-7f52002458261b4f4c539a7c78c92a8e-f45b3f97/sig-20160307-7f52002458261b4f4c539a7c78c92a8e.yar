rule sig_20160307_7f52002458261b4f4c539a7c78c92a8e {
  meta:
    description = "datamaliciousorder - file 20160307_7f52002458261b4f4c539a7c78c92a8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d205d01addb4aaffa718ac36393fcde64620d2862e65bf575305b822001c286"

  strings:
    $s1  = "hidden[ajax](udataCur + prefilterOrFactory, converters + cos + tweeners + tick + swap + etag + first + cssPrefixes + wrap, !(add" ascii
    $s2  = "scrollLeft = bindType[funescape + cssExpand + transport + sel + elementMatchers + holdReady + beforeSend](manipulationTarget + a" ascii
    $s3  = "scrollLeft = bindType[funescape + cssExpand + transport + sel + elementMatchers + holdReady + beforeSend](manipulationTarget + a" ascii
    $s4  = "tabIndex[padding + camelKey + outerCache] = (1 + -contentType);" fullword ascii
    $s5  = "bp[mapped + scripts + empty](scrollLeft, ((2 | cssFn), (47 | headers), (1 * iNoClone)));" fullword ascii
    $s6  = "Back == (Math.pow((((Math.pow(2 * expanded * 2, (fnOver ^ 2)) - t * 7) * ((slow, 62, val) - (37 + computed)) + ((13 | text) / (M" ascii
    $s7  = "bindType = uniqueSort[flatOptions + module + hasOwnProperty](restoreScript + unique + args + outermostContext);" fullword ascii
    $s8  = "empty = \"ile\", domManip = \"gReli\", restoreScript = \"WScri\", isArrayLike = 8, headers = 105, etag = \"scus.\";" fullword ascii
    $s9  = "hidden = class2type[chainable + checked + file][name + createHTMLDocument + stateVal + hasOwnProperty](propFilter + slideUp + ge" ascii
    $s10 = "class2type[reset + attachEvent + unique][username + when](((1750 / computed) - (59 * iNoClone + 32)));" fullword ascii
    $s11 = "checked = \"cr\", scripts = \"veToF\", username = \"Slee\", old = 137, prefilterOrFactory = \"T\", ajaxHandleResponses = \"b\";" fullword ascii
    $s12 = "removeAttribute[contents + isPlainObject] = ((0 ^ contentType) * (0 ^ contentType));" fullword ascii
    $s13 = "statusText[reverse](scrollLeft.rnoContent(), (0 | fnOver), ((1 * fnOver) | (0 | fnOver)));" fullword ascii
    $s14 = " 31 / (bup ^ 15))), (((expanded - 5) | iNoClone))) - ((((328 - optSelected) - (47 + insertBefore)) - ((44 + slideToggle) + 2)) &" ascii
    $s15 = "beforeSend = \"ings\", transport = \"nd\", val = 48, getWindow = \"S\", cssFn = 13;" fullword ascii
    $s16 = "class2type = (((149 - orig) & (117 - tokens)), (((28 ^ old), (26 * elements + 20), (finalText - 29)), this));" fullword ascii
    $s17 = "while (hidden[implicitRelative + completeDeferred + size] < (0 | iNoClone) * (48 / timeout)) {" fullword ascii
    $s18 = "bp[push_native](hidden[realStringObj + inspectPrefiltersOrTransports + handler + keyHooks + optall]);" fullword ascii
    $s19 = "}, \"nme\"), slideToggle = 20, module = \"teOb\", funescape = \"Ex\", manipulationTarget = \"%T\";" fullword ascii
    $s20 = "bp = class2type[restoreScript + unique][name + elementMatcher + ajaxHandleResponses + hasOwnProperty](prevObject + newSelector +" ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}