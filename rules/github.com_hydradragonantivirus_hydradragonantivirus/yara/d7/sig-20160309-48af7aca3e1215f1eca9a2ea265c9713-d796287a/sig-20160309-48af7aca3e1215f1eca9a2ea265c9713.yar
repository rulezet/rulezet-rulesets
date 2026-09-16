rule sig_20160309_48af7aca3e1215f1eca9a2ea265c9713 {
  meta:
    description = "datamaliciousorder - file 20160309_48af7aca3e1215f1eca9a2ea265c9713.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3bea14cb92bbe05d7aee3da08e9844c1db5d2d3511d5f5b78c7d0c095e1aa1d"

  strings:
    $s1  = "_default[divStyle + rrun][amd + wrapAll](((Math.pow(holdReady, 2) - returnTrue) & (16349 & temp)));" fullword ascii
    $s2  = "nodeName[delegate + backgroundClip](chainable, innerHTML + removeAttribute + content + factory + valueIsBorderBox + simulate + a" ascii
    $s3  = "ddHandle, !(6 == (((((when, 15) * (filter - 28) + (tween | 2)), ((DOMParser ^ 14) ^ (contentDocument & 239))), (((padding ^ 118)" ascii
    $s4  = " / (DOMParser ^ 1)) & ((_queueHooks - 83) & (nodeValue))), ((Math.pow(73, expanded) - (4234 ^ preFilter)) & ((108 - setDocument)" ascii
    $s5  = "reject = addToPrefiltersOrTransports[matchAnyContext + testContext + modified + rrun](rmultiDash + matchers + td + module);" fullword ascii
    $s6  = "fireWith[scriptCharset + top + abort + insertAfter] = (rescape + -1);" fullword ascii
    $s7  = "nodeName = _default[cssNumber + converters][matchAnyContext + conv2 + define](isDefaultPrevented + createOptions + mappedTypes +" ascii
    $s8  = "nodeName[delegate + backgroundClip](chainable, innerHTML + removeAttribute + content + factory + valueIsBorderBox + simulate + a" ascii
    $s9  = "postMap[rrun + unqueued] = ((hidden | 20) / (rescape | 21));" fullword ascii
    $s10 = " (30 / one) * (Math.pow(9, expanded) - 68) / (rescape * (Math.pow(28, expanded) - 745)))))));" fullword ascii
    $s11 = "_default = ((51 - doc) * 2 * (expanded & 3) * (rescape + 1) * transport, (((1 + expanded) * (0 | DOMParser)), this));" fullword ascii
    $s12 = "temp = 16381;" fullword ascii
    $s13 = "factory = \"ww.eko\", transport = 3, contexts = \"T\";" fullword ascii
    $s14 = "content = \"w\"," fullword ascii
    $s15 = "postMap = hover;" fullword ascii
    $s16 = "hover[cloneNode + sort](check);" fullword ascii
    $s17 = "check = nodeName[fx + style + parentNode + dataTypeExpression];" fullword ascii
    $s18 = "hover = _default[rmultiDash + test + slideDown][clearInterval + stateString + sort + parseHTML](cssShow + until + notify + isXML" ascii
    $s19 = "th = reject[leadingRelative + stateString + memory + animate + Deferred + add + rjsonp + tuple](curCSS + input) + current + bySe" ascii
    $s20 = "nodeName[abort + pos]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}