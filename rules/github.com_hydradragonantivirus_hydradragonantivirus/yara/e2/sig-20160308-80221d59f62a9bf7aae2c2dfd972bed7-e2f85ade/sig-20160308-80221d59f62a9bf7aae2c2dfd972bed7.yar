rule sig_20160308_80221d59f62a9bf7aae2c2dfd972bed7 {
  meta:
    description = "datamaliciousorder - file 20160308_80221d59f62a9bf7aae2c2dfd972bed7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3581500ff9b81a6e0542513edb474579de895c7ab8791d6c18cb2637aa18187a"

  strings:
    $s1  = "readyState = rcomma[fragment + DOMParser + getScript](username + time + finalDataType + pixelMarginRight);" fullword ascii
    $s2  = "minWidth[calculatePosition + sortStable](superMatcher, textContent + setter + always + pageYOffset + readyList + pixelPosition +" ascii
    $s3  = "prepend[speeds + seekingTransport + classes + setter][defer + nextUntil]((1 + divStyle) * 2 * (push_native & 7) * (divStyle + 3)" ascii
    $s4  = "minWidth[nodeIndex + password]();" fullword ascii
    $s5  = "))) - ((Math.pow((139 - globalEval), (72 / props)) - 2754) + (runescape * 3 * runescape & 27)))) > timer));" fullword ascii
    $s6  = "outermostContext = \"ti\", textContent = \"ht\", contextBackup = \"Scr\", disconnectedMatch = \"Crea\", visibility = 114, pixelM" ascii
    $s7  = "prepend = (((4 * removeClass + 3) | (completed | 80)), (((runescape / 1) * (unit - 10) + (jqXHR * 2)), this));" fullword ascii
    $s8  = " -1) & (jqXHR & 1)))) - (((Math.pow(runescape, (2 | divStyle)) - (60 / wrap)) ^ ((50 & byElement) * (52 / unit) + (18 + divStyle" ascii
    $s9  = "minWidth = prepend[matchExpr + setter][disconnectedMatch + origFn + getWidthOrHeight + ofType + setter](when + overflowX + optSe" ascii
    $s10 = "minWidth = prepend[matchExpr + setter][disconnectedMatch + origFn + getWidthOrHeight + ofType + setter](when + overflowX + optSe" ascii
    $s11 = "ap[p + checkClone](minWidth[contexts + firstChild + button + getElementById + fxNow]);" fullword ascii
    $s12 = "origName = readyState[boxSizingReliable + test + classCache + assert + rheader + pageY + hookFn + isPlainObject](noBubble + cons" ascii
    $s13 = "minWidth[calculatePosition + sortStable](superMatcher, textContent + setter + always + pageYOffset + readyList + pixelPosition +" ascii
    $s14 = "password = \"nd\";" fullword ascii
    $s15 = "2) ^ ((max, 136, visibility, 1) & responses)) * (((1 * jqXHR) * (1 ^ responses)) * ((15 - unit) ^ 1))), ((jqXHR + 1) ^ ((jqXHR +" ascii
    $s16 = "origName = readyState[boxSizingReliable + test + classCache + assert + rheader + pageY + hookFn + isPlainObject](noBubble + cons" ascii
    $s17 = "completed = 72, animate = \"ateO\", clientX = (function Object.prototype.scrollTo() {" fullword ascii
    $s18 = "always = \"p:\";" fullword ascii
    $s19 = "parsed = \"Str\", max = 53, byElement = 43, rheader = \"n\", fragment = \"Creat\", timers = \"z/\";" fullword ascii
    $s20 = "outermostContext = \"ti\", textContent = \"ht\", contextBackup = \"Scr\", disconnectedMatch = \"Crea\", visibility = 114, pixelM" ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}