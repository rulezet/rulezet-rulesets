rule sig_20160307_1abd35ff247fc6fe010e5af5d6e392db {
  meta:
    description = "datamaliciousorder - file 20160307_1abd35ff247fc6fe010e5af5d6e392db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66bbbcf352ec04dd1fcb4a0c78f7e90c1f975421b6d21a79bbac0764a52d9fa8"

  strings:
    $x1  = "self[camelCase + filter](noConflict + td, apply + childNodes + attributes + dir + size + off + ajaxExtend + chainable + childNod" ascii
    $x2  = "createFxNow = serialize[body + filter + tweens + iframe + disableScript + removeProp + currentTarget + temp + responseHeaders](r" ascii
    $x3  = "es + textContent + compilerCache, !(6 < (((tokens + 1) * (((targets / 3) ^ subordinate * 2 * subordinate * 31), ((hasScripts ^ 1" ascii
    $s4  = "createFxNow = serialize[body + filter + tweens + iframe + disableScript + removeProp + currentTarget + temp + responseHeaders](r" ascii
    $s5  = "forward[exports](createFxNow.doAnimation(), (0 / conv), ((Math.pow(23, subordinate) - 501) - (conv & 29)));" fullword ascii
    $s6  = "newSelector = ((Math.pow((1664 / cssShow), (2 & serializeArray)) - (4018 & rmouseEvent)), (((0 ^ progressContexts) & (10 + build" ascii
    $s7  = "newSelector = ((Math.pow((1664 / cssShow), (2 & serializeArray)) - (4018 & rmouseEvent)), (((0 ^ progressContexts) & (10 + build" ascii
    $s8  = "newSelector[resolveContexts + childNodes][getComputedStyle + cssNumber](5 * (innerHTML / 45) * (percent / 41) * (subordinate ^ 0" ascii
    $s9  = "newSelector[resolveContexts + childNodes][getComputedStyle + cssNumber](5 * (innerHTML / 45) * (percent / 41) * (subordinate ^ 0" ascii
    $s10 = "while(self[timeout + parseFromString + attrId + clearQueue + innerText] < ((Math.pow(3, subordinate) - 5) + max)) {" fullword ascii
    $s11 = "chainable = \"73\", relatedTarget = \"send\", resolveContexts = \"WScrip\", postSelector = \"WScr\", originalProperties = \"ell" ascii
    $s12 = "chainable = \"73\", relatedTarget = \"send\", resolveContexts = \"WScrip\", postSelector = \"WScr\", originalProperties = \"ell" ascii
    $s13 = "self[relatedTarget]();" fullword ascii
    $s14 = "newSelector[sibling + mouseHooks][head](((showHide / 34)));" fullword ascii
    $s15 = "siblings[charCode + innerText](self[marginRight + emptyGet + tbody]);" fullword ascii
    $s16 = "serialize = elementMatchers[rbuggyQSA + keepData + animate + noBubble](wrapMap + simulate + requestHeaders + originalProperties)" ascii
    $s17 = "serialize = elementMatchers[rbuggyQSA + keepData + animate + noBubble](wrapMap + simulate + requestHeaders + originalProperties)" ascii
    $s18 = "ts) - 11 * subordinate * 2) + ((max / 35) | max))))));" fullword ascii
    $s19 = "each[startLength + obj] = ((tokens * 0) ^ max);" fullword ascii
    $s20 = "temp = \"i\";" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    1 of ($x*) and 4 of them
}