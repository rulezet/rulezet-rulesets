rule sig_20160311_addd1e0b26c14b70e8d4c132104e48e9 {
  meta:
    description = "datamaliciousorder - file 20160311_addd1e0b26c14b70e8d4c132104e48e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64af66063f618a591cacca3a4a20f0a7259efead74bcad531721df11260dd31f"

  strings:
    $x1  = "delegateTarget[bp + \"pe\" + contextBackup](\"G\" + iframe + \"T\".jqXHR(), rprotocol + \"/nro.\" + sortStable + \"/23r35\" + co" ascii
    $s2  = "/ (Math.pow((Math.pow(target, 2) - pageX), (1 * setMatched)) - (299 - parent))) * (((136 & nextSibling) - 7 * siblingCheck * 3)," ascii
    $s3  = "8) / setMatched * 2 * seekingTransport)) + ((((116 - num) & (8 * seekingTransport + 4)) / ((target * 2 + setMatched) | (5 * setM" ascii
    $s4  = "delegateTarget = toSelector[\"WSc\" + responseHeadersString][\"Create\".jqXHR() + createComment + \"ct\"](fadeTo + \"ML2.X\" + m" ascii
    $s5  = "pipe[ajaxSetup + \"eTo\" + ajax](unmatched, ((Math.pow(firstElementChild, 2) - col) - (1 * responseType)));" fullword ascii
    $s6  = "delegateTarget = toSelector[\"WSc\" + responseHeadersString][\"Create\".jqXHR() + createComment + \"ct\"](fadeTo + \"ML2.X\" + m" ascii
    $s7  = " ((dataShow - 66), (run + 24)), ((contents - 53), (hasFocus / 45), (createPositionalPseudo / 10), (replaceAll & 223)), ((val | 4" ascii
    $s8  = "holdReady[timeout + \"n\".jqXHR()](unmatched.jqXHR(((preferredDoc - 27) * (createHTMLDocument | 5) + (toggleClass, 120, rnoConte" ascii
    $s9  = " target = 10," fullword ascii
    $s10 = "pipe = toSelector[\"WScr\" + rbuggyMatches][\"Crea\".jqXHR() + support + \"jec\" + remaining](\"ADOD\" + optionSet + \"eam\".jqX" ascii
    $s11 = "delegateTarget[getAllResponseHeaders + \"n\" + caption]();" fullword ascii
    $s12 = "pipe[bp + \"pe\" + contextBackup]();" fullword ascii
    $s13 = " + \"5\".jqXHR(), !(((((58 - ct) & (42 / suffix)) - ((2 | setMatched) + (101, setMatched))) * ((5 * setMatched + 3) * (left / 45" ascii
    $s14 = "))), ((34 / second) * 0), (rhash & (1 * createHTMLDocument)));" fullword ascii
    $s15 = "temp = \"Create\", amd = \"seBo\", setMatched = 2;" fullword ascii
    $s16 = "fireWith = marginDiv[temp + \"Obj\" + querySelectorAll](\"WSc\".jqXHR() + eventPath + \"hel\" + outerCache);" fullword ascii
    $s17 = "lastChild[\"t\" + empty + \"e\".jqXHR()] = ((1 * createHTMLDocument) & (1 | rhash));" fullword ascii
    $s18 = "matches = pipe;" fullword ascii
    $s19 = "lastChild = pipe;" fullword ascii
    $s20 = "contents = 119, contextBackup = \"n\";" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    1 of ($x*) and 4 of them
}