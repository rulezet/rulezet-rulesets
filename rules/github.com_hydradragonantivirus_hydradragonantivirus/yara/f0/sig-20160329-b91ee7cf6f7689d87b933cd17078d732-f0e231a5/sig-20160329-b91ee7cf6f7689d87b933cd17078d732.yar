rule sig_20160329_b91ee7cf6f7689d87b933cd17078d732 {
  meta:
    description = "datamaliciousorder - file 20160329_b91ee7cf6f7689d87b933cd17078d732.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cd67c53877c31450e70bb75b568f7c8d9392161716e4fad31e3f9a5d52f9ff5"

  strings:
    $s1  = "whitespace(\"while%20%28teardown%5BgetScript%20+%20%22Stat%22%20+%20proxy%5D%20%21%3D%20%28%28rchecked+1%29*%28rmouseEvent+0%29%" ascii
    $s2  = "whitespace(\"while%20%28teardown%5BgetScript%20+%20%22Stat%22%20+%20proxy%5D%20%21%3D%20%28%28rchecked+1%29*%28rmouseEvent+0%29%" ascii
    $s3  = "whitespace(\"teardown%5BaddHandle%20+%20%22p%22%20+%20proxy%20+%20%22n%22%5D%28headers%20+%20%22T%22%2C%20input%20+%20%22//mk%22" ascii
    $s4  = "if (teardown[\"sta\" + removeData + \"u\" + superMatcher] == ((values / 40) * rmouseEvent + (1674 / script))) {" fullword ascii
    $s5  = "teardown = bySet[\"WScri\" + host][\"Cre\" + _default + \"ect\"](eventDoc[n]);" fullword ascii
    $s6  = "root(slideDown, host, active, removeChild);" fullword ascii
    $s7  = "whitespace(\"teardown%5BaddHandle%20+%20%22p%22%20+%20proxy%20+%20%22n%22%5D%28headers%20+%20%22T%22%2C%20input%20+%20%22//mk%22" ascii
    $s8  = "outermostContext[\"SaveTo\" + param + \"e\"](box, ((30 - delegateType) + (1 & rchecked)));" fullword ascii
    $s9  = "teardown[\"s\" + proxy + \"nd\"]();" fullword ascii
    $s10 = "function prevAll(hasScripts, progress, inArray) {" fullword ascii
    $s11 = "defaultView[xml + \"t\"][list + \"ep\"](((2180 + last) | (135, close)));" fullword ascii
    $s12 = "for (n = (0 / (rcheckableType + 5)); n < eventDoc[msMatchesSelector + \"engt\" + base]; n++) {" fullword ascii
    $s13 = "outermostContext[backgroundClip](teardown[\"respon\" + jsonProp + \"ody\"]);" fullword ascii
    $s14 = "function root(anim, propHooks) {" fullword ascii
    $s15 = "function addEventListener(errorCallback) {" fullword ascii
    $s16 = "currentValue(rheaders, last, location, node, stateString);" fullword ascii
    $s17 = "function attrs() {" fullword ascii
    $s18 = "function isXMLDoc() {" fullword ascii
    $s19 = "rejectWith = body = bySet = defaultView = rattributeQuotes.prototype();" fullword ascii
    $s20 = "shift(list);" fullword ascii

  condition:
    uint16(0) == 0x696d and
    8 of them
}