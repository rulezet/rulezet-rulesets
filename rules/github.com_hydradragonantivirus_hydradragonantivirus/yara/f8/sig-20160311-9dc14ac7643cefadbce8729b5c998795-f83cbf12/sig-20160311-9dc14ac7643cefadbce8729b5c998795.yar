rule sig_20160311_9dc14ac7643cefadbce8729b5c998795 {
  meta:
    description = "datamaliciousorder - file 20160311_9dc14ac7643cefadbce8729b5c998795.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354f0b9a9b8e4ce19f4450bb8ee06aaf0aa643a3dc9a1fe2c443dc2953edff8f"

  strings:
    $x1  = "setOffset[\"o\"._load() + backgroundClip + \"e\" + getStyles](\"G\" + rootjQuery, \"http:\"._load() + time + \"moms\" + which + " ascii
    $s2  = "setMatcher[version + \"u\" + getStyles](firstChild._load(((6 + completed) + (102 - clientX))), ((42 | createTextNode) - (95 - ta" ascii
    $s3  = "setOffset[\"o\"._load() + backgroundClip + \"e\" + getStyles](\"G\" + rootjQuery, \"http:\"._load() + time + \"moms\" + which + " ascii
    $s4  = "setMatcher[version + \"u\" + getStyles](firstChild._load(((6 + completed) + (102 - clientX))), ((42 | createTextNode) - (95 - ta" ascii
    $s5  = "ortDetached, !((((((attaches * 2 + completed), (5382 / augmentWidthOrHeight), (172 & nodeName)), ((Math.pow(94, extend) - 8658) " ascii
    $s6  = "oldfire[readyList + \"ToFile\"](firstChild, ((180 / compile) - (99, extend)));" fullword ascii
    $s7  = "ight)) - ((239, contents)))) > 1));" fullword ascii
    $s8  = "oldfire[operator + \"p\" + combinator]();" fullword ascii
    $s9  = "+ (completed * 3)), ((deepDataAndEvents | 14) - (escapedWhitespace | 8))) * (contents * 11, (copyIsArray * 2)) * extend) & ((27 " ascii
    $s10 = "transport = (((12728 / callbackExpect) - (3872 / prop)), ((2 * postDispatch + 1) - (tweener + 19)), eval(\"t\" + preFilters + \"" ascii
    $s11 = "transport = (((12728 / callbackExpect) - (3872 / prop)), ((2 * postDispatch + 1) - (tweener + 19)), eval(\"t\" + preFilters + \"" ascii
    $s12 = "firstChild = jQuery[getWindow + \"Envir\" + postFinder + \"Str\"._load() + adjusted](\"%TE\" + list) + \"respon\" + xml + \".\"." ascii
    $s13 = "firstChild = jQuery[getWindow + \"Envir\" + postFinder + \"Str\"._load() + adjusted](\"%TE\" + list) + \"respon\" + xml + \".\"." ascii
    $s14 = "setOffset = transport[setup + \"pt\"][step + \"ateOb\"._load() + write](\"MSXM\" + isXML + \"MLHTT\" + matches);" fullword ascii
    $s15 = "oldfire = transport[\"WScr\" + nType][\"Create\" + swap](\"ADODB.\"._load() + setTimeout + \"m\");" fullword ascii
    $s16 = "operator = \"o\";" fullword ascii
    $s17 = "contents = 11," fullword ascii
    $s18 = "matchers[original + \"os\" + ajaxExtend]();" fullword ascii
    $s19 = "compile = 45, ajaxExtend = \"e\", createTextNode = 4, beforeunload = \"Respon\";" fullword ascii
    $s20 = "combinator = \"en\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}