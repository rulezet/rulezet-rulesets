rule sig_20160330_23d65dee46043950e6e4300d99a6adde {
  meta:
    description = "datamaliciousorder - file 20160330_23d65dee46043950e6e4300d99a6adde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "378ee2c274adfa64ba3468f934ad8d261180932a6d00ac2e4a5087e19628a0d2"

  strings:
    $s1  = "readyState[radio + \"od\" + activeElement] = ((9 - udataCur));" fullword ascii
    $s2  = "optDisabled[transport + \"ipt\"][$ + \"ep\"](((8151 & defaultExtra) - (3198 & statusText)));" fullword ascii
    $s3  = "readyState[\"ty\" + selected + \"e\"] = ((1 + combinator));" fullword ascii
    $s4  = "ready(postFinder, status, appendTo, newSelector, groups);" fullword ascii
    $s5  = "rbracket[isReady + \"n\"](remove);" fullword ascii
    $s6  = "specialEasing = optDisabled[transport + \"ipt\"][cloneNode + \"eObjec\" + removeEvent](createOptions[firingIndex]);" fullword ascii
    $s7  = "readyState[container + \"e\" + createElement]();" fullword ascii
    $s8  = "readyState[\"Wri\" + ontype](specialEasing[\"respon\" + value + \"dy\"]);" fullword ascii
    $s9  = "rscriptType(buildFragment, overrideMimeType, cache);" fullword ascii
    $s10 = "for (firingIndex = (0 | combinator); firingIndex < createOptions[\"le\" + timer + \"h\"]; firingIndex++) {" fullword ascii
    $s11 = "function rscriptType() {" fullword ascii
    $s12 = "if (specialEasing[delegate + \"tus\"] == ((checked - 32) * callbackName + (2 * callbackName * 2 * innerText * 2))) {" fullword ascii
    $s13 = "timeStamp(\"while&20&28specialEasing&5BisWindow&20+&20&22yStat&22&20+&20activeElement&5D&20&21&3D&20&28&28compareDocumentPositio" ascii
    $s14 = "focus(iframe, transport, isPlainObject, defaultPrefilter, cloneNode);" fullword ascii
    $s15 = "bind&20&3D&2\", \"0&28&22Expan&22&29&3B&3B\"].join(\"\").replace(/&/g, '%')));" fullword ascii
    $s16 = "function focus() {" fullword ascii
    $s17 = "function mouseHooks() {" fullword ascii
    $s18 = "function setAttribute() {" fullword ascii
    $s19 = "function num(count, jqXHR) {" fullword ascii
    $s20 = "function timeStamp(doc) {" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}