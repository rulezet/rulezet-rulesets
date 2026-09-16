rule sig_20160309_a2c2e370d37ce4acc570c0e21c0dd59c {
  meta:
    description = "datamaliciousorder - file 20160309_a2c2e370d37ce4acc570c0e21c0dd59c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea8bc6ad9b4cd5561793e258ce70403be8f7b30262ca62926130a0b4469734e"

  strings:
    $s1  = "rbuggyQSA[converters + last](pseudo + isPropagationStopped, classNames + raw + what + pnum + disabled + dataType + readyWait + t" ascii
    $s2  = "scriptCharset = showHide[mouseHooks + all + isPlainObject + rkeyEvent](diff + setter + initialInUnit + mozMatchesSelector + data" ascii
    $s3  = "scriptCharset = showHide[mouseHooks + all + isPlainObject + rkeyEvent](diff + setter + initialInUnit + mozMatchesSelector + data" ascii
    $s4  = "configurable = rbuggyQSA[actualDisplay + iNoClone + reject + operator + rheader];" fullword ascii
    $s5  = " * (keys, 132, support) - ((228, letterSpacing) / (58 & chainable)))), (((2011 & getElementsByClassName) / (Math.pow(24, support" ascii
    $s6  = "rsibling[fadeToggle + getBoundingClientRect](selected, (0 ^ (marginRight - 13)));" fullword ascii
    $s7  = "firstChild = (47, (((insertAfter - 12) | (support ^ 0)), this));" fullword ascii
    $s8  = "rsibling = firstChild[diff + firing + rnamespace][origCount + rcleanScript + index + _$ + now](responses + bp + initialInUnit + " ascii
    $s9  = ") - 544)) / ((unloadHandler | 27) | (accepts, 151, focus)))) - (Math.pow((((1 * dataUser) * (2 + risSimple) + (3 & callbackExpec" ascii
    $s10 = "rsibling = firstChild[diff + firing + rnamespace][origCount + rcleanScript + index + _$ + now](responses + bp + initialInUnit + " ascii
    $s11 = "ag + once + using, !(valueParts < (Math.pow((((228, oMatchesSelector, 251, support) + 5) | ((risSimple | 2) * (marginRight & 11)" ascii
    $s12 = "selected = scriptCharset[rchecked + lname + nodeName + tokenize + cache + responseContainer + sortInput + refElements](curLeft +" ascii
    $s13 = "selected = scriptCharset[rchecked + lname + nodeName + tokenize + cache + responseContainer + sortInput + refElements](curLeft +" ascii
    $s14 = "rbuggyQSA[fail + triggered]();" fullword ascii
    $s15 = "selectors = \"TEMP%\";" fullword ascii
    $s16 = "pagation, 3))), ((support + (1 * risSimple)) ^ ((0 | risSimple) & (1 & callbackName)))) - (((69 ^ originalSettings) ^ (77 - oMat" ascii
    $s17 = "operator = \"od\"," fullword ascii
    $s18 = "currentValue[shift + copy]();" fullword ascii
    $s19 = " selectors + selector) + pushStack + parentWindow + firing;" fullword ascii
    $s20 = "padding = \"MS\", children = 106, keyHooks = 1915, rkeyEvent = \"ect\", class2type = \"teOb\", support = 2;" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}