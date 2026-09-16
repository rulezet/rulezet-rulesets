rule sig_20160309_1d40bca4505019307195fcf9235991a8 {
  meta:
    description = "datamaliciousorder - file 20160309_1d40bca4505019307195fcf9235991a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54df91744a714978af3028e76fc68a0d89c043e5d749fe433b34347983271802"

  strings:
    $s1  = ")) & ((3 ^ manipulationTarget) * 2 + (compareDocumentPosition - 7))) & (((Math.pow(done, 2) - rclickable) - (8 & timeout)) & (Ma" ascii
    $s2  = "opacity[statusCode](container.options(), ((1 ^ manipulationTarget) + -(1 + manipulationTarget)), ((1 * manipulationTarget) / (Ma" ascii
    $s3  = "originalEvent[cors + subordinate](r20, msg + propFix + delegate + cache + doAnimation + el + second + nonce + height + rreturn +" ascii
    $s4  = "opacity[statusCode](container.options(), ((1 ^ manipulationTarget) + -(1 + manipulationTarget)), ((1 * manipulationTarget) / (Ma" ascii
    $s5  = "operator = ((0 ^ (file & 31)), ((manipulationTarget | (30 & pixelMarginRightVal)), this));" fullword ascii
    $s6  = "sibling[nextUntil + tr + addCombinator](container, ((Math.pow(disable, 2) - ontype) / (Math.pow(26, inspect) - 638)));" fullword ascii
    $s7  = "container = margin[curLeft + isSimulated + replaceAll + prevObject + isWindow + returnFalse](eventDoc + tweener) + reject + iter" ascii
    $s8  = "ator + relatedTarget + getPropertyValue + jqXHR + selection + factory;" fullword ascii
    $s9  = "sibling = operator[noGlobal + height][duration + htmlPrefilter + keys + height](expanded + wrapInner + Expr + end + eventPath + " ascii
    $s10 = "sibling = operator[noGlobal + height][duration + htmlPrefilter + keys + height](expanded + wrapInner + Expr + end + eventPath + " ascii
    $s11 = "pseudo[height + animated] = ((39 & jsonp) - (Math.pow(33, inspect) - 1055));" fullword ascii
    $s12 = "th.pow(28, inspect) - 746)));" fullword ascii
    $s13 = "th.pow((1 * progressValues), (3 & inspect)) - (261 / unqueued)))))));" fullword ascii
    $s14 = "tr = \"eT\", noGlobal = \"WScrip\", values = \".S\", eventDoc = \"%TEMP%\";" fullword ascii
    $s15 = " (((243, timers, 1) | manipulationTarget) * ((7 & all) & (7 & p)))) & ((((1 * concat) * (199, unique, 2) + (focus, 196, booleans" ascii
    $s16 = "margin = isLocal[isBorderBox + tweeners + rdisplayswap](dir + overrideMimeType + height + values + bubbleType);" fullword ascii
    $s17 = "isLocal = operator[cos + clientY + step + tag];" fullword ascii
    $s18 = "originalEvent = operator[clientX + stopPropagation][cached + seekingTransport + detach + rdisplayswap](createPositionalPseudo + " ascii
    $s19 = "originalEvent = operator[clientX + stopPropagation][cached + seekingTransport + detach + rdisplayswap](createPositionalPseudo + " ascii
    $s20 = "sibling[children + identifier]();" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}