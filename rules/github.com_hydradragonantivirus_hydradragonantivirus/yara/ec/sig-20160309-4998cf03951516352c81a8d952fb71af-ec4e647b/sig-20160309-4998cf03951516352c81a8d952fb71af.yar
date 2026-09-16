rule sig_20160309_4998cf03951516352c81a8d952fb71af {
  meta:
    description = "datamaliciousorder - file 20160309_4998cf03951516352c81a8d952fb71af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa55e99d740e791945e131541bb3dd0dad2689b9fd1bda087b8f66f0880b7757"

  strings:
    $s1  = "rejectWith[beforeunload + getElementsByClassName + access](destElements, guid + clientY + clearQueue + postSelector + fixInput +" ascii
    $s2  = "uniqueSort = matchesSelector[defaultValue + prev][scrollTo + getClientRects + bindType + left](hover + hidden + insertAfter);" fullword ascii
    $s3  = " dir + multipleContexts + elementMatcher + contents + orig, !(((((isSimulated / 47) & (Math.pow(isNumeric, 2) - rbuggyMatches)) " ascii
    $s4  = "reject[adjustCSS](createButtonPseudo.getPropertyValue(), ((14 * ajax + 6) - (attrNames | 34)), ((writable + 0) * (b & 1)));" fullword ascii
    $s5  = "duration[password + cloneNode]();" fullword ascii
    $s6  = "createButtonPseudo = attachEvent[charCode + top + curPosition + wrapInner + height + getElementsByClassName + access + createCom" ascii
    $s7  = "matchesSelector = (((86 + ap) - (Math.pow(83, ajax) - 6741)), (((Math.pow(rnotwhite, 2) - visibility) + 1), this));" fullword ascii
    $s8  = "current = \"w\", cssShow = \"WScrip\", open = \"HTTP\", password = \"cl\";" fullword ascii
    $s9  = "rejectWith = matchesSelector[defaultValue + prev][parents + bindType + left](inspectPrefiltersOrTransports + base + open);" fullword ascii
    $s10 = "createButtonPseudo = attachEvent[charCode + top + curPosition + wrapInner + height + getElementsByClassName + access + createCom" ascii
    $s11 = "1) + (b | 2))) / ((((documentIsHTML + 452) / (rcheckableType & 14)) + (writable * 2) * (ajax * 3 + writable)) & ((3 * memory - (" ascii
    $s12 = "/ ((1 & writable) * (225 / converters))) * ((192 * ajax + 39) / (writable ^ 8)) * (((then / 32), (indirect | 4)) - ((writable * " ascii
    $s13 = "51 - converters)), (67 & types) * (3 + b), ((680 / td) * (0 | bulk) + (3 ^ b))))) == 6));" fullword ascii
    $s14 = "var parseFromString = \"TEMP%\"," fullword ascii
    $s15 = "matchesSelector[cssShow + left][jsonpCallback + whitespace](((Math.pow(215, ajax) - 46001), (Math.pow(deepDataAndEvents, 2) - bl" ascii
    $s16 = "reliableMarginRight = rejectWith[results + closest + append + dirruns];" fullword ascii
    $s17 = "matchesSelector[cssShow + left][jsonpCallback + whitespace](((Math.pow(215, ajax) - 46001), (Math.pow(deepDataAndEvents, 2) - bl" ascii
    $s18 = "var whitespace = (function Object.prototype.getPropertyValue() {" fullword ascii
    $s19 = "getClientRects = \"reat\", pdataCur = \"rs\", results = \"R\", reverse = \"posit\";" fullword ascii
    $s20 = "rejectWith[beforeunload + getElementsByClassName + access](destElements, guid + clientY + clearQueue + postSelector + fixInput +" ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}