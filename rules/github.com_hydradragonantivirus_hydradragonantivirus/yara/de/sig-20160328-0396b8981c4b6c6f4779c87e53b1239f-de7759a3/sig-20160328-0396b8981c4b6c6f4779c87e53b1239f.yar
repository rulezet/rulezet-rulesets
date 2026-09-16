rule sig_20160328_0396b8981c4b6c6f4779c87e53b1239f {
  meta:
    description = "datamaliciousorder - file 20160328_0396b8981c4b6c6f4779c87e53b1239f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c99c2ef5f1234feb52da38c8c0f568a3d1aec7395dbd2d3d518217fddae75649"

  strings:
    $x1  = "eval(responseText(\"global%20%3D%20%28%220%22%29%3Bprop%20%3D%20%282854%29%3B%20fxNow%20%3D%20%28%22File%22%29%3B%20_%20%3D%20%2" ascii
    $s2  = "while(tweens[\"read\" + sibling + \"ate\"] != ((hasContent - 82) / (triggered - 60))) dataTypes[replaceChild + \"ript\"][view]((" ascii
    $s3  = "while(tweens[\"read\" + sibling + \"ate\"] != ((hasContent - 82) / (triggered - 60))) dataTypes[replaceChild + \"ript\"][view]((" ascii
    $s4  = "if(tweens[\"status\"] == ((253, completed, 28, r20) - (41 | excess))) {" fullword ascii
    $s5  = "aup[content](tweens[\"respo\" + clearCloneStyle + \"dy\"]);" fullword ascii
    $s6  = "aup[access + \"de\"] = ((170 / excess) - (1 * isPlainObject));" fullword ascii
    $s7  = "aup[\"SaveTo\" + fxNow](noop, ((elementMatcher - 98), (originalSettings + 94), (setter / 20), (isPlainObject + 0)));" fullword ascii
    $s8  = "results(responseText(\"noop%20%3D%20throws%5B%22Expand%22%20+%20handlerQueue%20+%20%22onme%22%20+%20p%20+%20%22trings%22%5D%28is" ascii
    $s9  = "for(refElements = (dataAttr, 192, locked, 0); refElements < contextBackup[\"le\" + responseType]; refElements++) {" fullword ascii
    $s10 = "removeData[\"WScri\" + removeAttr][\"Sleep\"](((promise, 91, method, 7082) & (prop * 2 + id)));" fullword ascii
    $s11 = "throws[index + \"un\"](noop);" fullword ascii
    $s12 = "play%20%3D%20%28%22l2.XML%22%29%3Bcharset%20%3D%20%28function%20Sizzle%28%29%7B%7D%2C%20%22Msx%22%29%3B%20onabort%20%3D%20%28%22" ascii
    $s13 = "function curCSS() {" fullword ascii
    $s14 = "function box() {" fullword ascii
    $s15 = "function indirect() {" fullword ascii
    $s16 = "results(responseText(\"noop%20%3D%20throws%5B%22Expand%22%20+%20handlerQueue%20+%20%22onme%22%20+%20p%20+%20%22trings%22%5D%28is" ascii
    $s17 = "eval(responseText(\"global%20%3D%20%28%220%22%29%3Bprop%20%3D%20%282854%29%3B%20fxNow%20%3D%20%28%22File%22%29%3B%20_%20%3D%20%2" ascii
    $s18 = "function clientTop(delegate, bp, splice) {" fullword ascii
    $s19 = "clientTop(dataAttr, ap, prevUntil, index);" fullword ascii
    $s20 = "indirect(promise, rnamespace);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}