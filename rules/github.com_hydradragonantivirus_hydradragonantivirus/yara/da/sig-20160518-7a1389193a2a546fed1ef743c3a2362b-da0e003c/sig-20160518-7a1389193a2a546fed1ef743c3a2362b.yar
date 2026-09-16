rule sig_20160518_7a1389193a2a546fed1ef743c3a2362b {
  meta:
    description = "datamaliciousorder - file 20160518_7a1389193a2a546fed1ef743c3a2362b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "879b832e5823daca3a4a45031c3297cc00a7c7a32436b121c20d551d7b1a8c34"

  strings:
    $s1  = "var sizes = [mildew, concentric,doggerel,  \"\"+\".\"+(\"india\",\"alfred\",\"patriarchal\",\"tally\",\"depict\",\"albania\",\"f" ascii
    $s2  = "var spiritual=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".compare4())&&entitle[\"c3RhdHVz\".compare4()] +\"\"==\"MjAw\".comp" ascii
    $s3  = "var spiritual=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".compare4())&&entitle[\"c3RhdHVz\".compare4()] +\"\"==\"MjAw\".comp" ascii
    $s4  = "weasel = ((\"deduction\", \"elation\", \"wrestler\", \"greenland\", \"ECpLMGRmYpX\") + \"KPgVtcVgxVJ\").compare2();" fullword ascii
    $s5  = "proceed = ((\"treatment\", \"census\", \"concerning\", \"younger\", \"pwSaRdrxS\") + \"dtbNSot\").compare2();" fullword ascii
    $s6  = "String.prototype.compare = function () {" fullword ascii
    $s7  = "String.prototype.compare4 = function() {" fullword ascii
    $s8  = "String.prototype.compare2 = function () {" fullword ascii
    $s9  = "        explorer[(proceed + \"o\"+(\"nonsensical\",\"circles\",\"walked\",\"automobile\",\"julia\",\"translator\",\"researcher\"" ascii
    $s10 = "var mildew = \"QWinfraN0aXZinfralWE9iainframVjdA=infra=\".compare4();" fullword ascii
    $s11 = "var doggerel =\"JVinfraRFTVinfraAl\".compare4();" fullword ascii
    $s12 = "var concentric =\"RXhwYW5infrakRW52aXinfraJvbm1lbnRTdHJinfrapbmdz\".compare4();" fullword ascii
    $s13 = "        explorer[\"d3JpdGU=\".compare4()](entitle[(\"officiating\",\"stimuli\",\"headphones\",\"channel\",\"dulcet\",\"advertisi" ascii
    $s14 = "reduce = reduce+ sizes.shift();" fullword ascii
    $s15 = "var drudgery = sizes.pop().split(\">\");" fullword ascii
    $s16 = "cayman = \"b3Blbg==\".compare4();;" fullword ascii
    $s17 = "        explorer[\"d3JpdGU=\".compare4()](entitle[(\"officiating\",\"stimuli\",\"headphones\",\"channel\",\"dulcet\",\"advertisi" ascii
    $s18 = "    adjutant.barbados = adjutant.mighty[\"c3Vic3RyaW5n\".compare4()](procreation, magnum);" fullword ascii
    $s19 = "var sizes = [mildew, concentric,doggerel,  \"\"+\".\"+(\"india\",\"alfred\",\"patriarchal\",\"tally\",\"depict\",\"albania\",\"f" ascii
    $s20 = "  sloppy = [];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}