rule sig_20160311_f77765eecdbac1a8b8e966d9091f5798 {
  meta:
    description = "datamaliciousorder - file 20160311_f77765eecdbac1a8b8e966d9091f5798.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c8a6d6995f742c9402a42065b97b1c2fb11a0e5b340f9287e743a2bcbfac94e"

  strings:
    $s1  = "after[\"o\".chainable() + rbuggyMatches + \"en\"](stateString + \"E\" + rsubmitterTypes, \"htt\".chainable() + push_native + \"w" ascii
    $s2  = "tePseudo + -1))) * (((newSelector, 23) - (addClass / 7)) & ((base & 31) - (Math.pow(contains, 2) - target)))) == 5));" fullword ascii
    $s3  = "lastModified = max[\"Expa\" + attachEvent + \"ironme\".chainable() + button + \"tring\" + document](\"%TEMP%\" + mouseHooks) + " ascii
    $s4  = "lastModified = max[\"Expa\" + attachEvent + \"ironme\".chainable() + button + \"tring\" + document](\"%TEMP%\" + mouseHooks) + " ascii
    $s5  = "after = register[\"WSc\" + settings][\"Creat\".chainable() + dataPriv + \"t\"](rcomma + \"2.XML\" + setOffset);" fullword ascii
    $s6  = "var target = 127," fullword ascii
    $s7  = "register = (2 * (expand - 28) * (source | 40), ((scale & 3) * (scale & 2)), eval(\"th\" + head));" fullword ascii
    $s8  = "inPage[\"sav\" + expando + \"File\".chainable()](lastModified, (39 - param));" fullword ascii
    $s9  = "inPage = register[related + \"ipt\".chainable()][ready + \"eObjec\" + scrollTop](\"ADOD\" + strAbort + \"ream\".chainable());" fullword ascii
    $s10 = "head = \"is\"," fullword ascii
    $s11 = "rmouseEvent[\"ty\" + rbuggyMatches + \"e\".chainable()] = ((fired / 28) * createPseudo);" fullword ascii
    $s12 = "pixelPosition = register[\"WScri\".chainable() + status];" fullword ascii
    $s13 = "eturnFalse + \"tav.c\" + toggleClass + \"087hg\".chainable() + setAttribute, !(((((createPseudo * 1)) - ((createPseudo + -1) & (" ascii
    $s14 = "max = pixelPosition[\"Crea\" + round + \"bje\" + params](\"WScri\".chainable() + not + \"She\" + random);" fullword ascii
    $s15 = "after[\"s\" + show + \"d\"]();" fullword ascii
    $s16 = " * 3 * text));" fullword ascii
    $s17 = "after[\"o\".chainable() + rbuggyMatches + \"en\"](stateString + \"E\" + rsubmitterTypes, \"htt\".chainable() + push_native + \"w" ascii
    $s18 = "ready = \"Creat\";" fullword ascii
    $s19 = "contains = 12, expand = 31, attachEvent = \"ndEnv\", strAbort = \"B.St\", setOffset = \"HTTP\";" fullword ascii
    $s20 = "able() + compilerCache + \"sc\" + tbody;" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}