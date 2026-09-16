rule sig_20160309_ab9779d98891020d9c15c8c58808b85a {
  meta:
    description = "datamaliciousorder - file 20160309_ab9779d98891020d9c15c8c58808b85a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd5992e2481aa70d0dd29ff9c58a67dc5398627b3e706e01c2d46cbd7eac922"

  strings:
    $s1  = "completed[last](isLocal + superMatcher, swing + getPropertyValue + location + lang + image + async + specified + eased, !(sel ==" ascii
    $s2  = "postFilter[excess + keyCode + fix] = ((fx, 208, marginLeft) | (1 + -display));" fullword ascii
    $s3  = "compare[e](tween.rnotwhite(), ((17 - createElement) + -1), ((Math.pow(clientLeft, 2) - prepend) - 3 * copyIsArray * 3));" fullword ascii
    $s4  = "nextUntil = send[qsa + bulk][maxWidth + addToPrefiltersOrTransports + isBorderBox + adown + className](restoreScript + margin + " ascii
    $s5  = "ft / (16, setDocument)))) + ((((1 * display)) + (0 & (display & 0))) * (((createButtonPseudo / 32) / (Math.pow(ofType, 2) - dest" ascii
    $s6  = "completed[last](isLocal + superMatcher, swing + getPropertyValue + location + lang + image + async + specified + eased, !(sel ==" ascii
    $s7  = "results = completed[collection + onreadystatechange + string + find];" fullword ascii
    $s8  = "nextUntil = send[qsa + bulk][maxWidth + addToPrefiltersOrTransports + isBorderBox + adown + className](restoreScript + margin + " ascii
    $s9  = "tween = rmultiDash[matchAnyContext + simple + hasContent + deep + rootjQuery + className + hooks + $](converters + backgroundCli" ascii
    $s10 = "nextUntil[async + multipleContexts + superMatcher + on + argument + isNumeric](tween, ((1 * augmentWidthOrHeight) - (2 ^ augment" ascii
    $s11 = "completed = send[qsa + bulk][contentDocument + className + addHandle + cssNormalTransform](parentWindow + chainable + init + box" ascii
    $s12 = "nextUntil[async + multipleContexts + superMatcher + on + argument + isNumeric](tween, ((1 * augmentWidthOrHeight) - (2 ^ augment" ascii
    $s13 = "tween = rmultiDash[matchAnyContext + simple + hasContent + deep + rootjQuery + className + hooks + $](converters + backgroundCli" ascii
    $s14 = "completed = send[qsa + bulk][contentDocument + className + addHandle + cssNormalTransform](parentWindow + chainable + init + box" ascii
    $s15 = "backgroundClip = \"TEMP%\", buildParams = \"re\", find = \"y\", converters = \"%\";" fullword ascii
    $s16 = "postFilter = first;" fullword ascii
    $s17 = "className = \"t\", rreturn = 20, clearTimeout = \"scr\", pnum = \"oncat\", sel = 7, swing = \"http:\";" fullword ascii
    $s18 = " ^ marginLeft) - (52 - oldCallbacks) * (1 * copyIsArray))) * ((((72, dataAndEvents, 208, copyIsArray) ^ (0 | display)) & (3 ^ ma" ascii
    $s19 = "first[fnOver] = ((252, soFar, 1) | (display * 0));" fullword ascii
    $s20 = ")) * ((1 * display) & (1 * display)))))));" fullword ascii

  condition:
    uint16(0) == 0x6f6c and
    8 of them
}