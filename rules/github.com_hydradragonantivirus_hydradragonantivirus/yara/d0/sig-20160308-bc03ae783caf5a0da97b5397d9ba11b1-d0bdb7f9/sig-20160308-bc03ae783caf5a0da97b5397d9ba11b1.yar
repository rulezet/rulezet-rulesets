rule sig_20160308_bc03ae783caf5a0da97b5397d9ba11b1 {
  meta:
    description = "datamaliciousorder - file 20160308_bc03ae783caf5a0da97b5397d9ba11b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91e5bedc3f3c9ce8c9d8dc4bbe888a0c8be3a5b729daba26d8c7afadb0178679"

  strings:
    $s1  = "noBubble[lastChild + attr + replaceChild](until, tokenCache + outermost + onreadystatechange + serializeArray + defer + targets " ascii
    $s2  = "noBubble[lastChild + attr + replaceChild](until, tokenCache + outermost + onreadystatechange + serializeArray + defer + targets " ascii
    $s3  = "noBubble = cssProps[view + proxy][defaultPrevented + head + replaceAll](stored + completeDeferred + assert + isTrigger);" fullword ascii
    $s4  = "cssProps[createCache + progressContexts][pipe + attr](((specialEasing / 32) * trim + (Math.pow(14, trim) - 172)));" fullword ascii
    $s5  = "pos = \"Cr\", proxy = \"ipt\", related = \"Sle\", targets = \"67u\", invert = \"WScri\";" fullword ascii
    $s6  = "protocol[ret](cleanData.merge(), ((14 ^ binary) - (1520 / binary)), ((0 ^ undelegate) / 5));" fullword ascii
    $s7  = "while (noBubble[parse + sort] < ((undelegate) | (Math.pow(3, trim) - 5))) {" fullword ascii
    $s8  = "cssProps = ((17 * (checked * 2 + trim) + (16 + undelegate)), ((43 - rprotocol), this));" fullword ascii
    $s9  = ")) - (14148124 * checked + 7552604)));" fullword ascii
    $s10 = "cssProps[createCache + progressContexts][related + sourceIndex]((Math.pow((prevUntil * 8 + attributes), (222, current, 154, trim" ascii
    $s11 = "rsingleTag = cssProps[invert + startTime][pos + each + len + position](hasData + dataTypeOrTransport + j + toggle);" fullword ascii
    $s12 = "rsingleTag[propFix + responseType + readyWait](noBubble[activeElement + nextSibling + option + Expr]);" fullword ascii
    $s13 = "html = addHandle[keyHooks + swing + innerHTML + progressContexts](index + size + rdisplayswap + speeds);" fullword ascii
    $s14 = "+ cos + relative, !(9 < ((((stopImmediatePropagation & 1) + (runescape - 49)) | (overflow & 15)))));" fullword ascii
    $s15 = "pipe = \"Slee\";" fullword ascii
    $s16 = "head = \"eOb\";" fullword ascii
    $s17 = "cleanData = html[fnOver + cssHooks + linear + superMatcher + concat + postFilter](pointerenter + stored + isTrigger + ajaxExtend" ascii
    $s18 = "cleanData = html[fnOver + cssHooks + linear + superMatcher + concat + postFilter](pointerenter + stored + isTrigger + ajaxExtend" ascii
    $s19 = "until = \"GET\";" fullword ascii
    $s20 = ") + w + isXMLDoc + wait + curCSSLeft + responseType;" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}