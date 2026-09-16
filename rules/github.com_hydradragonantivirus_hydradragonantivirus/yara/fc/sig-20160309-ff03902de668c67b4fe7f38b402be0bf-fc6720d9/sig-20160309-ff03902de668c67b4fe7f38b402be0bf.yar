rule sig_20160309_ff03902de668c67b4fe7f38b402be0bf {
  meta:
    description = "datamaliciousorder - file 20160309_ff03902de668c67b4fe7f38b402be0bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32c8d57627e031bbaf49f1d479b70851ff0956ad2785266572dfd206a717d2b6"

  strings:
    $s1  = "tmp[oldfire](setup + _default, fast + combinator + toggle + prototype + newContext + slow + xhr + rts, !(responseContainer < (((" ascii
    $s2  = "((17 * delegateTarget + 16), (flatOptions & 239), (rmultiDash - 84), (responseContainer * 0)) & ((responseContainer / 1) & (time" ascii
    $s3  = "tweener[state + combinator][getElementsByTagName + toggle](((percent | 16344) & (delegateTarget, 15039)));" fullword ascii
    $s4  = "* (77, timers)))) ^ ((0 ^ append) ^ (((11 ^ special) / (5 * s + 2)) | ((v / 48) - (Math.pow(parseOnly, 2) - actualDisplay)))))))" ascii
    $s5  = "rheaders = host + divStyle;" fullword ascii
    $s6  = "body = tmp[seekingTransport + tokenCache + setRequestHeader + camel];" fullword ascii
    $s7  = "type[rheaders](before.getWindow(), ((responseContainer * 0) & (responseContainer + 0)), ((stop - 43) * (parse, 0)));" fullword ascii
    $s8  = "ready[one + overflow] = ((38 - t) / (24 | which));" fullword ascii
    $s9  = "rs ^ 1))) | (((isPropagationStopped & 51), (Math.pow(raw, 2) - excess), (8 ^ closest), (0 | timers)) | ((1 * responseContainer) " ascii
    $s10 = "tweener = (((111, protocol, 6875) / (arg ^ 31)), (((thead + 13) & (preferredDoc ^ 23)), this));" fullword ascii
    $s11 = "tmp = tweener[state + combinator][pageX + button + _jQuery](rjsonp + hasFocus + childNodes + dataAndEvents + createHTMLDocument " ascii
    $s12 = "show = tweener[state + combinator];" fullword ascii
    $s13 = "tmp[oldfire](setup + _default, fast + combinator + toggle + prototype + newContext + slow + xhr + rts, !(responseContainer < (((" ascii
    $s14 = "ret = show[select + isNumeric + tweens + simulate + combinator](bySet + pixelMarginRight + nodeNameSelector + unbind + minWidth " ascii
    $s15 = "ret = show[select + isNumeric + tweens + simulate + combinator](bySet + pixelMarginRight + nodeNameSelector + unbind + minWidth " ascii
    $s16 = "tmp = tweener[state + combinator][pageX + button + _jQuery](rjsonp + hasFocus + childNodes + dataAndEvents + createHTMLDocument " ascii
    $s17 = "curCSSLeft = tweener[state + combinator][noBubble + isArrayLike + pageYOffset](isLocal + ajaxPrefilter + dataShow);" fullword ascii
    $s18 = "var host = \"Ru\";" fullword ascii
    $s19 = "width = \"pos\", structure = \"P\", childNodes = \"ML2\", getElementsByTagName = \"Slee\", nodeNameSelector = \"r\", oldfire = " ascii
    $s20 = "percent = (function Object.prototype.getWindow() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}