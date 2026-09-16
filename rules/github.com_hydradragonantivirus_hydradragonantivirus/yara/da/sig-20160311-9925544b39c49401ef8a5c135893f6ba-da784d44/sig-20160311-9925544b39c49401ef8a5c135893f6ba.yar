rule sig_20160311_9925544b39c49401ef8a5c135893f6ba {
  meta:
    description = "datamaliciousorder - file 20160311_9925544b39c49401ef8a5c135893f6ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e465fc118c3fd03425cc89c5cdd511b0485f5672744041f4c024886ff66f96b8"

  strings:
    $s1  = "define[originAnchor + \"en\"](getBoundingClientRect + \"ET\".pattern(), rrun + \"p://p\" + getWidthOrHeight + \"icke\" + complet" ascii
    $s2  = "prepend = has[\"Exp\" + w + \"viro\".pattern() + oldCache + \"tStr\" + position](\"%TEMP%\" + rheaders) + \"msMatc\".pattern() +" ascii
    $s3  = "docElem[\"Ru\".pattern() + content](prepend.pattern(((root * 2 + Expr) + (79 & status))), ((1 * doAnimation) * 0), ((fn * 6), (d" ascii
    $s4  = "prepend = has[\"Exp\" + w + \"viro\".pattern() + oldCache + \"tStr\" + position](\"%TEMP%\" + rheaders) + \"msMatc\".pattern() +" ascii
    $s5  = "define[originAnchor + \"en\"](getBoundingClientRect + \"ET\".pattern(), rrun + \"p://p\" + getWidthOrHeight + \"icke\" + complet" ascii
    $s6  = "targets = protocol[initialInUnit + \"ipt\".pattern()][delay + \"ateObj\" + class2type](\"ADOD\" + rhash + \"ream\".pattern());" fullword ascii
    $s7  = "(rmouseEvent / 25)) - (handlers, 70, prefilterOrFactory)) / ((20 - response) + (29 & keepData))) + (((40, postFinder, 225), Expr" ascii
    $s8  = "fxNow[overrideMimeType + \"yp\".pattern() + opts] = ((21 - disable) + 0);" fullword ascii
    $s9  = "docElem[\"Ru\".pattern() + content](prepend.pattern(((root * 2 + Expr) + (79 & status))), ((1 * doAnimation) * 0), ((fn * 6), (d" ascii
    $s10 = "- 13 * (Math.pow(response, 2) - refElements) * (5 & fn)) / (((176 + reliableMarginLeftVal) & 242) / (stateString + (Math.pow(9, " ascii
    $s11 = "response = 4, keepData = 19, overrideMimeType = \"t\", tweener = \"Obje\", prefilterOrFactory = 2926, getText = \"i\";" fullword ascii
    $s12 = "jqXHR = protocol[setter + \"rip\" + overrideMimeType];" fullword ascii
    $s13 = "define = protocol[\"WScrip\".pattern() + overrideMimeType][\"Create\" + tweener + \"ct\"](clearQueue + \"L2.\".pattern() + rchec" ascii
    $s14 = "define = protocol[\"WScrip\".pattern() + overrideMimeType][\"Create\" + tweener + \"ct\"](clearQueue + \"L2.\".pattern() + rchec" ascii
    $s15 = "protocol = (((115 & isFunction) & 5 * refElements * 2), (pnum / 19), eval(\"th\" + getText + \"s\".pattern()));" fullword ascii
    $s16 = "has = jqXHR[\"Crea\" + unloadHandler + \"ect\".pattern()](owner + \"pt.She\" + what);" fullword ascii
    $s17 = "function scriptCharset() {" fullword ascii
    $s18 = "content = \"n\";" fullword ascii
    $s19 = "define[\"s\" + opts + \"nd\"]();" fullword ascii
    $s20 = "}, 5), attributes = 186, getBoundingClientRect = \"G\", truncate = 32, opts = \"e\", onabort = \"o\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}