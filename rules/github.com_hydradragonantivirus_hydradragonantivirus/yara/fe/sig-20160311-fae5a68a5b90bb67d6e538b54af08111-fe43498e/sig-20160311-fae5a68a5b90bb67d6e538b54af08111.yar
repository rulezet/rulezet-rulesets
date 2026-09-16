rule sig_20160311_fae5a68a5b90bb67d6e538b54af08111 {
  meta:
    description = "datamaliciousorder - file 20160311_fae5a68a5b90bb67d6e538b54af08111.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c7b8edc8b04a956bc38d471013100cb6c2f38f8171b12d287b7edff63a2a2f5"

  strings:
    $s1  = "returned[cacheURL + \"pe\".indirect() + risSimple](\"GE\" + guid, \"http\" + testContext + \"28.21\".indirect() + rprotocol + \"" ascii
    $s2  = "getResponseHeader + \"i76u5y\" + hasData, !(8 == (((last / 14) * (isReady | 42), ((originalOptions + 98) - progressValues), ((Ma" ascii
    $s3  = "parentWindow = dataType[list + \"dEnv\" + scripts + \"entStr\".indirect() + slideToggle + \"s\"](box + \"/\") + setRequestHeader" ascii
    $s4  = "dy) + (36 / postMap))) / (((4 + root) + (8 | rjsonp)) / ((12144 / holdReady) / 3 * makeArray))))));" fullword ascii
    $s5  = "rfocusable[clearInterval + \"n\"](parentWindow.indirect((Math.pow((73 & defer), (1 * resolveWith)) - (41920 / adjustCSS))), ((1 " ascii
    $s6  = "insertBefore) + -1), ((newDefer & 31) - (Math.pow(view, 2) - fireWith)));" fullword ascii
    $s7  = "rfocusable[clearInterval + \"n\"](parentWindow.indirect((Math.pow((73 & defer), (1 * resolveWith)) - (41920 / adjustCSS))), ((1 " ascii
    $s8  = "box = \"%TEMP%\"," fullword ascii
    $s9  = "parentWindow = dataType[list + \"dEnv\" + scripts + \"entStr\".indirect() + slideToggle + \"s\"](box + \"/\") + setRequestHeader" ascii
    $s10 = "dataType = firstDataType[stored + \"ateO\" + contents](\"WScrip\".indirect() + isArray + \"ell\");" fullword ascii
    $s11 = "value[hasContent + \"en\".indirect()]();" fullword ascii
    $s12 = "returned = aup[letterSpacing + \"pt\"][stored + \"ate\".indirect() + selectors](\"MSX\" + pnum + \"MLHTTP\");" fullword ascii
    $s13 = "value = aup[letterSpacing + \"pt\"][raw + \"Obj\".indirect() + visibility](\"ADODB\" + dataUser + \"am\");" fullword ascii
    $s14 = "arg[getClientRects + \"y\" + cacheLength + \"e\"] = (2 * globalEventContext * 2 * resolveWith / (16 | blur));" fullword ascii
    $s15 = "filter = \"w\", raw = \"Create\", setRequestHeader = \"que\", parseOnly = 1, rprotocol = \"1.19\", num = \"i\";" fullword ascii
    $s16 = "contents = \"bject\"," fullword ascii
    $s17 = "firstDataType = aup[constructor + \"t\"];" fullword ascii
    $s18 = "returned[\"se\".indirect() + risSimple + \"d\"]();" fullword ascii
    $s19 = "value[\"saveT\".indirect() + refElements](parentWindow, 2);" fullword ascii
    $s20 = "root = 4;" fullword ascii

  condition:
    uint16(0) == 0x6976 and
    8 of them
}