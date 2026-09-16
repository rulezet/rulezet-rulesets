rule sig_20160311_d0cdb295f0824970fd98a8f46f8416f7 {
  meta:
    description = "datamaliciousorder - file 20160311_d0cdb295f0824970fd98a8f46f8416f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ebd832e1c8437727a98bac2356a16a2c29e6f02b5950272cefee6409142082a"

  strings:
    $s1  = "soFar[\"op\".caption() + progress](\"G\" + access, \"http:\" + delegate + \"lita\".caption() + promise + \"z/095\" + adjustCSS +" ascii
    $s2  = "textContent = iframe[mappedTypes + \"and\" + complete + \"ronme\".caption() + camelKey + \"rings\"](dirrunsUnique + \"MP%/\") + " ascii
    $s3  = " 52)) - ((strAbort, 27, getAllResponseHeaders) - (42 | scrollTop))) / (((Math.pow(17, structure) - 265) | (converters - 46)) & (" ascii
    $s4  = "toggle[\"saveT\" + getElementsByTagName + \"le\"](textContent, ((1 * structure)));" fullword ascii
    $s5  = "textContent = iframe[mappedTypes + \"and\" + complete + \"ronme\".caption() + camelKey + \"rings\"](dirrunsUnique + \"MP%/\") + " ascii
    $s6  = "tContext & 15))) / (((rnamespace | 114), (Math.pow(noop, 2) - bind)) / ((449 | Symbol) / (32 | timer)))) + (((60 + (rnamespace +" ascii
    $s7  = "iframe = visible[bindType + \"ateO\" + xhrFields](\"WSc\".caption() + len + \"Shell\");" fullword ascii
    $s8  = "soFar = transport[combinator + \"pt\"][run + \"teO\".caption() + xhrFields](\"MSX\" + compiled + \"MLHTT\" + noGlobal);" fullword ascii
    $s9  = "soFar[\"op\".caption() + progress](\"G\" + access, \"http:\" + delegate + \"lita\".caption() + promise + \"z/095\" + adjustCSS +" ascii
    $s10 = "transport = (((189 & shift), (3441 / overflowX), (28 - to), (1105 / children)), (0 | (animation - 16)), eval(\"t\" + blur + \"s" ascii
    $s11 = "transport = (((189 & shift), (3441 / overflowX), (28 - to), (1105 / children)), (0 | (animation - 16)), eval(\"t\" + blur + \"s" ascii
    $s12 = "visible = transport[n + \"t\"];" fullword ascii
    $s13 = "toggle = transport[\"WScr\" + contexts][\"Crea\" + styles + \"ect\".caption()](nodeType + \"B.Str\" + optgroup);" fullword ascii
    $s14 = "scripts = toggle;" fullword ascii
    $s15 = "eval(unescape(\"%20%20%20%20%20%20%20%20transport%5Bcombinator%20+%20%22pt%22%5D%5Banim%5D%28%28239*structure*%28992/seed%29+%28" ascii
    $s16 = "prefilterOrFactory + 17) * structure)))));" fullword ascii
    $s17 = "toggle[\"op\" + progress]();" fullword ascii
    $s18 = "complete = \"Envi\";" fullword ascii
    $s19 = "combinator = \"WScri\";" fullword ascii
    $s20 = "var bind = 63515," fullword ascii

  condition:
    uint16(0) == 0x656c and
    8 of them
}