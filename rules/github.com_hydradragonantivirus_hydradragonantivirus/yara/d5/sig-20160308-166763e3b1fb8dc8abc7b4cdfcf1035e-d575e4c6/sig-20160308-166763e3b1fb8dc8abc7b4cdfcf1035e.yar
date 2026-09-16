rule sig_20160308_166763e3b1fb8dc8abc7b4cdfcf1035e {
  meta:
    description = "datamaliciousorder - file 20160308_166763e3b1fb8dc8abc7b4cdfcf1035e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63b5938e8de084e7fabe4953bf91dce906a60e287e8242349b66a4ccffd1e3a6"

  strings:
    $s1  = " / (25 | inArray))) / (((28 & getElementsByName) * (12 - xhrFields) + (4 + rsingleTag)) & ((93 & restoreScript) - (75 - matcher)" ascii
    $s2  = "nodeNameSelector[settings](guid + fireGlobals, markFunction + returned + splice + testContext + trim + globalEventContext + dete" ascii
    $s3  = "nodeNameSelector = p[attrHooks + _default][status + dataFilter + host + body + getComputedStyle](Data + err + elemLang + initial" ascii
    $s4  = "nodeNameSelector = p[attrHooks + _default][status + dataFilter + host + body + getComputedStyle](Data + err + elemLang + initial" ascii
    $s5  = "exports[lname + initial + node + swap](removeAttribute, ((17, script, 2, rclickable) - (408 / aup)));" fullword ascii
    $s6  = "p = (3 * (Math.pow(noCloneChecked, 2) - w), (((46 / setTimeout) * (3 & finalValue)), this));" fullword ascii
    $s7  = "postSelector = errorCallback[getJSON + superMatcher + Sizzle](index + matcherFromGroupMatchers + timer + runescape + reject);" fullword ascii
    $s8  = "removeAttribute = postSelector[optDisabled + chainable + special + pos + responseContainer + open](rfxtypes + radioValue + regis" ascii
    $s9  = "removeAttribute = postSelector[optDisabled + chainable + special + pos + responseContainer + open](rfxtypes + radioValue + regis" ascii
    $s10 = "errorCallback = p[promise + contents + fix];" fullword ascii
    $s11 = "p[seed + always][rbracket + charCode](((34203 - result) - (8304 | type)));" fullword ascii
    $s12 = "exports[assert + r20]();" fullword ascii
    $s13 = "exports = p[seed + always][status + responses + adown + _default](boxSizingReliableVal + focusin + mappedTypes + rsibling);" fullword ascii
    $s14 = "ctDuplicates + fast + delegateCount, !(8 == (((((Math.pow(jQuery, 2) - lastChild) ^ (481 / rsingleTag)) - ((9194 - offsetParent)" ascii
    $s15 = "script = 207;" fullword ascii
    $s16 = "promise = \"WS\", rclickable = 19, host = \"eat\", boxSizingReliableVal = \"ADOD\";" fullword ascii
    $s17 = "contents = \"c\";" fullword ascii
    $s18 = "while (nodeNameSelector[mappedTypes + escapedWhitespace + isXMLDoc] < ((div | 10) - finalValue * 2)) {" fullword ascii
    $s19 = "nodeNameSelector[settings](guid + fireGlobals, markFunction + returned + splice + testContext + trim + globalEventContext + dete" ascii
    $s20 = "ter + beforeunload + firstDataType) + rtypenamespace + detach + ajax + _default + r20 + base + initialInUnit + tr;" fullword ascii

  condition:
    uint16(0) == 0x6373 and
    8 of them
}