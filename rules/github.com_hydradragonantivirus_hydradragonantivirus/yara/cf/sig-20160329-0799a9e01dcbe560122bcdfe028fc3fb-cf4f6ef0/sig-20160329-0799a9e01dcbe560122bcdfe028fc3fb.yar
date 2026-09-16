rule sig_20160329_0799a9e01dcbe560122bcdfe028fc3fb {
  meta:
    description = "datamaliciousorder - file 20160329_0799a9e01dcbe560122bcdfe028fc3fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad4eb5d05cf1fcd088985af878ac355e5b653b218bd2596a3ce8345bab2c26db"

  strings:
    $s1  = "responseHeadersString[namespaces + \"pt\"][list + \"leep\"](((146 & param), (245000 / getScript)));" fullword ascii
    $s2  = "filter(\"jQuery%20%3D%20responseHeadersString%5B%22WScrip%22%20+%20rscriptType%5D%5B%22Cre%22%20+%20username%20+%20%22bjec%22%20" ascii
    $s3  = "filter(\"jQuery%20%3D%20responseHeadersString%5B%22WScrip%22%20+%20rscriptType%5D%5B%22Cre%22%20+%20username%20+%20%22bjec%22%20" ascii
    $s4  = "using[styles + \"oFile\"](currentTarget, (2 | selected));" fullword ascii
    $s5  = "filter(\"currentTarget%20%3D%20overflowY%5B%22Expan%22%20+%20isImmediatePropagationStopped%20+%20%22viron%22%20+%20replaceChild%" ascii
    $s6  = "filter(\"Deferred%28%22http%3A%22%20+%20sortStable%20+%20%22ale%22%20+%20unwrap%20+%20%22afe%22%20+%20selector%20+%20%22gequ%22%" ascii
    $s7  = "for (setRequestHeader = (1 * (cssNumber * 0)); setRequestHeader < handleObjIn[\"l\" + binary]; setRequestHeader++) {" fullword ascii
    $s8  = "filter(\"currentTarget%20%3D%20overflowY%5B%22Expan%22%20+%20isImmediatePropagationStopped%20+%20%22viron%22%20+%20replaceChild%" ascii
    $s9  = "function swap(unquoted, delegateTarget) {" fullword ascii
    $s10 = "using[rscriptType + \"yp\" + fns] = ((19 / hasDuplicate) * (26 / identifier));" fullword ascii
    $s11 = "filter(\"overflowY%20%3D%20fast%5B%22WScrip%22%20+%20rscriptType%5D%5B%22Creat%22%20+%20pageY%20+%20%22ect%22%5D%28namespaces%20" ascii
    $s12 = "filter(\"while%20%28jQuery%5B%22ready%22%20+%20progressContexts%5D%20%21%3D%20%28%284%7CisBorderBox%29%7C%280%7CisBorderBox%29%2" ascii
    $s13 = "function content(keyCode, preferredDoc) {" fullword ascii
    $s14 = "content(outermost, combinator);" fullword ascii
    $s15 = "using[combinator + \"e\" + parentOffset]();" fullword ascii
    $s16 = "filter(\"overflowY%20%3D%20fast%5B%22WScrip%22%20+%20rscriptType%5D%5B%22Creat%22%20+%20pageY%20+%20%22ect%22%5D%28namespaces%20" ascii
    $s17 = "function bool(namespace, postMap, parseFromString) {" fullword ascii
    $s18 = "filter(\"responseHeadersString%5Bnamespaces%20+%20%22pt%22%5D%5Bcontext%20+%20%22p%22%5D%28%28%28success*2*outermost%29+%284322+" ascii
    $s19 = "filter(\"responseHeadersString%5Bnamespaces%20+%20%22pt%22%5D%5Bcontext%20+%20%22p%22%5D%28%28%28success*2*outermost%29+%284322+" ascii
    $s20 = "responseHeadersString = handlerQueue = getElementById = fast = attr.sibling();" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}