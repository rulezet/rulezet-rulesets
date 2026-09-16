rule sig_20160309_5effa4c4fab8bae6128c14b87f846951 {
  meta:
    description = "datamaliciousorder - file 20160309_5effa4c4fab8bae6128c14b87f846951.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64df228a77bd7332eb2681e47dafd45faa048e619fabcbed70db14160016fe06"

  strings:
    $s1  = "elementMatchers[attrHandle + rinputs](promise, val + load + handlerQueue + handler + dirruns + tweener + getWindow + cssPrefixes" ascii
    $s2  = "bySet = register[namespace + unbind + bp + getJSON + xml](oMatchesSelector + dispatch + ajaxSetup);" fullword ascii
    $s3  = "elementMatchers[attrHandle + rinputs](promise, val + load + handlerQueue + handler + dirruns + tweener + getWindow + cssPrefixes" ascii
    $s4  = "elementMatchers = handlers[ignored + postFinder + conv][div1 + XMLHttpRequest + pop](rmultiDash + pattern + rmultiDash + split +" ascii
    $s5  = "elementMatchers = handlers[ignored + postFinder + conv][div1 + XMLHttpRequest + pop](rmultiDash + pattern + rmultiDash + split +" ascii
    $s6  = " + extra + computeStyleTests + push + v + using + e, !(detectDuplicates == ((((128, calculatePosition) & (Math.pow(11, text) - 1" ascii
    $s7  = "handlers[ignored + last + percent + noConflict][overrideMimeType + webkitMatchesSelector + etag + rattributeQuotes](((slideUp * " ascii
    $s8  = "what = elementMatchers[w + types + matchIndexes + originalEvent + source + getStyles];" fullword ascii
    $s9  = "qualifier = handlers[ignored + postFinder + conv][vendorPropName + offsetWidth + Sizzle + conv](slow + optionSet);" fullword ascii
    $s10 = "handlers[ignored + last + percent + noConflict][overrideMimeType + webkitMatchesSelector + etag + rattributeQuotes](((slideUp * " ascii
    $s11 = "el = \"po\", transport = \"ition\", promise = \"GET\";" fullword ascii
    $s12 = "urlAnchor[deep + etag] = ((37 - one) + 0);" fullword ascii
    $s13 = "alize + hidden) + origFn + pushStack + transport + responseType + preMap;" fullword ascii
    $s14 = "proxy[PI + originalEvent]();" fullword ascii
    $s15 = "select[el + clone + dirruns + realStringObj + createHTMLDocument] = ((parentNode, 224, next, 0) | (optSelected & 0));" fullword ascii
    $s16 = "qualifier[td + bool + compilerCache + webkitMatchesSelector](rwhitespace, ((ajaxExtend & 51) - (overflow & 31)));" fullword ascii
    $s17 = "rwhitespace = bySet[conditionFn + runescape + nextSibling + addEventListener + argument + dirruns + currentTime](matchers + seri" ascii
    $s18 = "rwhitespace = bySet[conditionFn + runescape + nextSibling + addEventListener + argument + dirruns + currentTime](matchers + seri" ascii
    $s19 = "register = handlers[diff + percent + noConflict];" fullword ascii
    $s20 = "2 + DOMParser) | 2 * ap * 3 * ap * 2 * ap * 5 * text));" fullword ascii

  condition:
    uint16(0) == 0x7572 and
    8 of them
}