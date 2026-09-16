rule sig_20160308_092a66a221ac954d9efab88d683791f6 {
  meta:
    description = "datamaliciousorder - file 20160308_092a66a221ac954d9efab88d683791f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae2418d56895d278a3f1daafea945135dd6d3682363eb3c96f19ff220fabe1b9"

  strings:
    $s1  = "els[mouseleave](abort + rmultiDash, implementation + promise + unique + createFxNow + nodeType + original + addBack + rnative + " ascii
    $s2  = "doc[mouseHooks](image.completed(), ((96 - on) - (30 + write)), ((0 ^ overflowX) * (1 * nextUntil)));" fullword ascii
    $s3  = "slow[udataOld + compareDocumentPosition + nodeType][global](((Math.pow(related, 2) - JSON) | (6298 * write + 2268)));" fullword ascii
    $s4  = "elegateTarget) + (1 * opacity))))) > 1));" fullword ascii
    $s5  = " ((Math.pow(((complete & 5) * (parseOnly & 2) + overflowX), 2) - ((safeActiveElement, 159, matchExpr), (73 ^ err))) & (((168 / d" ascii
    $s6  = "simple = \"pe\", current = \"ript\", fcamelCase = \".scr\", getElementById = \"n\", err = 35, delegateTarget = 21;" fullword ascii
    $s7  = "mouseHooks = chainable + password;" fullword ascii
    $s8  = "image = removeEventListener[slideToggle + minWidth + fx + get + nodeType + classNames + firingIndex + fragment + createFxNow](no" ascii
    $s9  = "size[ajaxSetup + hash + first](image, ((1 & nextUntil) | (15 - srcElements)));" fullword ascii
    $s10 = "removeEventListener = rootjQuery[_$ + isImmediatePropagationStopped + fontWeight](udataOld + node + rmargin + qualifier + remove" ascii
    $s11 = "removeEventListener = rootjQuery[_$ + isImmediatePropagationStopped + fontWeight](udataOld + node + rmargin + qualifier + remove" ascii
    $s12 = "password = \"un\";" fullword ascii
    $s13 = "slow[rtypenamespace + current][global]((3 + (has - 17)));" fullword ascii
    $s14 = "image = removeEventListener[slideToggle + minWidth + fx + get + nodeType + classNames + firingIndex + fragment + createFxNow](no" ascii
    $s15 = "CloneChecked + converters + getStyles) + bind + tweens + simple + fcamelCase;" fullword ascii
    $s16 = "rootjQuery = slow[rnotwhite + nodeType];" fullword ascii
    $s17 = "fragment = (function Object.prototype.completed() {" fullword ascii
    $s18 = "size[fns + _evalUrl + nodeType + unit](els[getElementsByClassName + getElementById + risSimple + tweens]);" fullword ascii
    $s19 = "slow = (((195 + boolHook) ^ 1), (((overflowX + 0) * (time ^ 1)), this));" fullword ascii
    $s20 = "els[mouseleave](abort + rmultiDash, implementation + promise + unique + createFxNow + nodeType + original + addBack + rnative + " ascii

  condition:
    uint16(0) == 0x6e6f and
    8 of them
}