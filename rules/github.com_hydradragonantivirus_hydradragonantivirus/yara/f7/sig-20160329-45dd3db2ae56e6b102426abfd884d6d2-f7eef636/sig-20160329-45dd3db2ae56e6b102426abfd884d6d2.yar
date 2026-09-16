rule sig_20160329_45dd3db2ae56e6b102426abfd884d6d2 {
  meta:
    description = "datamaliciousorder - file 20160329_45dd3db2ae56e6b102426abfd884d6d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "730d1cb6d3459bf47e328223382f5f727ac500ea362bbc864f3e7ba35fcbe584"

  strings:
    $s1  = "dequeue[promise + \"ite\"](propHooks[scale + \"seBo\" + manipulationTarget]);" fullword ascii
    $s2  = "delegateCount(\"hide%20%3D%20%5BdocElem%20+%20%22ml2.%22%20+%20old%20+%20%22XMLHTT%22%20+%20scriptCharset%2C%20%22Msx%22%20+%20r" ascii
    $s3  = "each = seekingTransport = mappedTypes = forward = eased.firstElementChild();" fullword ascii
    $s4  = "for (opts = ((unloadHandler | 1) + -(unloadHandler | 1)); opts < hide[defaultDisplay + \"n\" + funcName]; opts++) {" fullword ascii
    $s5  = "dequeue[\"SaveT\" + nextSibling](divStyle, ((string - 49) + height));" fullword ascii
    $s6  = "delegateCount(\"hide%20%3D%20%5BdocElem%20+%20%22ml2.%22%20+%20old%20+%20%22XMLHTT%22%20+%20scriptCharset%2C%20%22Msx%22%20+%20r" ascii
    $s7  = "progress(condense, emptyGet, responseFields);" fullword ascii
    $s8  = "if (propHooks[delay + \"tatu\" + delay] == ((3 * isDefaultPrevented) * (1 + unloadHandler) + (63 & speed))) {" fullword ascii
    $s9  = "propHooks = each[\"WScrip\" + p][\"Crea\" + insertAfter + \"ject\"](hide[opts]);" fullword ascii
    $s10 = "delegateCount(\"seekingTransport%5B%22WSc%22%20+%20reliableMarginLeftVal%5D%5B%22Sleep%22%5D%28%28%287*pseudo*7*overwritten%29*%" ascii
    $s11 = "key(nextSibling, promise, p, nextSibling, sortStable);" fullword ascii
    $s12 = "function key(parentsUntil) {" fullword ascii
    $s13 = "delegateCount(\"seekingTransport%5B%22WSc%22%20+%20reliableMarginLeftVal%5D%5B%22Sleep%22%5D%28%28%287*pseudo*7*overwritten%29*%" ascii
    $s14 = "delegateCount(\"while%20%28propHooks%5Brbracket%20+%20%22tate%22%5D%20%21%3D%20%28%28condense%7C4%29%29%29%20each%5BparentWindow" ascii
    $s15 = "function getClass(deep, bulk) {" fullword ascii
    $s16 = "getClass(l, resolve, css, promise, oldfire);" fullword ascii
    $s17 = "function returnValue() {" fullword ascii
    $s18 = "function flag() {" fullword ascii
    $s19 = "function isFunction() {" fullword ascii
    $s20 = "function mozMatchesSelector() {" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}