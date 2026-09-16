rule sig_20160308_6b8477972d340e581983226354e3ff34 {
  meta:
    description = "datamaliciousorder - file 20160308_6b8477972d340e581983226354e3ff34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e2d932bb0a22f569a1a3646795b3e92cad87bd77d2c70ff9f034fe5b0883326"

  strings:
    $s1  = "a = write[empty + target][rkeyEvent + scrollLeft + letterSpacing + childNodes + rfocusable + compareDocumentPosition](size + nam" ascii
    $s2  = "a = write[empty + target][rkeyEvent + scrollLeft + letterSpacing + childNodes + rfocusable + compareDocumentPosition](size + nam" ascii
    $s3  = "a[delegateTarget + checked + rcombinators](inspect, ((44 - delay) - 2 * jQuery * 2));" fullword ascii
    $s4  = "iterator[checkNonElements](outermostContext, returnValue + success + hasScripts + createHTMLDocument + rhash + ridentifier + boo" ascii
    $s5  = "while (iterator[when + flag + el + types + manipulationTarget] < (Math.pow((responseHeadersString ^ 3), jQuery) - (Math.pow(4, j" ascii
    $s6  = "while (iterator[when + flag + el + types + manipulationTarget] < (Math.pow((responseHeadersString ^ 3), jQuery) - (Math.pow(4, j" ascii
    $s7  = "iterator[checkNonElements](outermostContext, returnValue + success + hasScripts + createHTMLDocument + rhash + ridentifier + boo" ascii
    $s8  = "10 - send) & 3 * getClientRects * 7)) - (((responseHeadersString / 28) & (invert - 45)) | ((stateString + 203) / (sel | 8)))))))" ascii
    $s9  = "write[offsetWidth + rescape][namespaces + elements + dataShow]((jQuery | 0) * (Math.pow(rsubmitterTypes, 2) - rbrace) * (3 + res" ascii
    $s10 = "parts = \"%TEMP%\";" fullword ascii
    $s11 = "conditionFn[root + completeDeferred] = ((248, getElementsByClassName) | (0 | responseHeadersString));" fullword ascii
    $s12 = "target = \"pt\";" fullword ascii
    $s13 = "swing[prefilterOrFactory](inspect.parentsUntil(), ((what - 48) ^ (responseHeadersString & 1)), ((getElementsByClassName & 1) * (" ascii
    $s14 = "write = (((36 * jQuery + 18) ^ rejectWith * 2 * jQuery), (((3 + responseHeadersString) * (84 / init) + (42 / init)), this));" fullword ascii
    $s15 = "swing[prefilterOrFactory](inspect.parentsUntil(), ((what - 48) ^ (responseHeadersString & 1)), ((getElementsByClassName & 1) * (" ascii
    $s16 = "response = \"M\", colgroup = \"onm\", letterSpacing = \"eat\", returnValue = \"http\", dataTypeExpression = \"en\", responseHead" ascii
    $s17 = "Query) - 11))) {" fullword ascii
    $s18 = "response = \"M\", colgroup = \"onm\", letterSpacing = \"eat\", returnValue = \"http\", dataTypeExpression = \"en\", responseHead" ascii
    $s19 = "a[setTimeout + progress + completeDeferred]();" fullword ascii
    $s20 = "removeEventListener = write[empty + pnum + types];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}