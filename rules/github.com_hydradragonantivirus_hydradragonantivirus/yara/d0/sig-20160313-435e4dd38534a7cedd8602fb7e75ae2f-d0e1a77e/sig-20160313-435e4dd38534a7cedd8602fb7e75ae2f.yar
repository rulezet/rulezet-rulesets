rule sig_20160313_435e4dd38534a7cedd8602fb7e75ae2f {
  meta:
    description = "datamaliciousorder - file 20160313_435e4dd38534a7cedd8602fb7e75ae2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "475aee0e480cffc27d1b9269d252a9bc52b48824aeabf0506ced9b3dffa4800f"

  strings:
    $s1  = "time[\"op\" + caption + \"n\"](rnoInnerhtml + \"T\", responseType + \"://oh\" + fixHooks + \"uyff\" + cssNormalTransform + \"m/7" ascii
    $s2  = "f) | ((7 * (oMatchesSelector / 35) + (pipe - 42)) / ((errorCallback + 9) + tfoot))) - (Math.pow((33, clearCloneStyle, 85, queue)" ascii
    $s3  = "adown = this[access + \"ipt\"][delegate + \"eObjec\" + target](\"ADOD\" + copy + \"eam\");" fullword ascii
    $s4  = "time = this[\"WScri\" + createPseudo][\"Cre\" + includeWidth + \"bjec\" + target](\"MSXML\" + lastModified + \"MLH\" + sibling);" ascii
    $s5  = "test = defaultPrefilter[\"Expand\" + setMatchers + \"ron\" + m + \"Stri\" + tick](\"%TEMP\" + msFullscreenElement) + \"s\" + fir" ascii
    $s6  = "rt)))) - (((1213 & owner) / (Math.pow(13, queue) - 146)) * (nextAll - 39) * (rsibling / 30) + ((finalText - 70) | (rtagName | 34" ascii
    $s7  = "test = defaultPrefilter[\"Expand\" + setMatchers + \"ron\" + m + \"Stri\" + tick](\"%TEMP\" + msFullscreenElement) + \"s\" + fir" ascii
    $s8  = " * ((94 / rbuggyQSA) * 3 * readyList + (1 * find)), (((1056 / empty) / (246 / nextAll)) - ((1890 / fxNow) | (13 + seekingTranspo" ascii
    $s9  = "target = \"t\"," fullword ascii
    $s10 = "unquoted[\"t\" + curCSSLeft + \"p\" + caption] = ((Math.pow(resolveValues, 2) - currentTime) / (31 & seekingTransport));" fullword ascii
    $s11 = "tween[\"Ru\" + offsetParent](test, (mapped & (1 & find)), ((1 + mapped) + -(1 + mapped)));" fullword ascii
    $s12 = "adown[\"sav\" + isWindow + \"e\"](test, ((30, transports) / (16, diff, 55, winnow)));" fullword ascii
    $s13 = "pipe = 46;" fullword ascii
    $s14 = "isWindow = (function swap.responseHeadersString() {" fullword ascii
    $s15 = "defaultPrefilter = handler[expand + \"ateO\" + dest](\"WScri\" + current + \"hel\" + rinputs);" fullword ascii
    $s16 = "adown[tweeners + \"pe\" + offsetParent]();" fullword ascii
    $s17 = "View, !(2 == ((((rfocusMorph) / (15 | resolveValues)) * ((1 * queue) | (2 | mapped)) * ((145 / ontype) | (1 & find)) * (50 / dif" ascii
    $s18 = "time[\"s\" + fragment + \"d\"]();" fullword ascii
    $s19 = "copy = \"B.Str\"," fullword ascii
    $s20 = "h.pow%284366%2C%20queue%29-19054170%29%2C%20%28find+1%29%29-swing*71809*queue*2%29%29%3B%20%20%20%0D\"));" fullword ascii

  condition:
    uint16(0) == 0x776f and
    8 of them
}