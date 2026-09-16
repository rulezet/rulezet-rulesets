rule sig_20160517_a3c49e184d3533b26645d71a0b5a50d9 {
  meta:
    description = "datamaliciousorder - file 20160517_a3c49e184d3533b26645d71a0b5a50d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3a33035904eb9295a3be546014f85107553b521d0306319bfc9a06dee699b4"

  strings:
    $s1  = "            helterskelter[confusion]((\"listless\",\"brandishing\",\"G\" + weasel) + (\"apostolic\",\"victim\",\"stuck\",\"colon" ascii
    $s2  = "            helterskelter[confusion]((\"listless\",\"brandishing\",\"G\" + weasel) + (\"apostolic\",\"victim\",\"stuck\",\"colon" ascii
    $s3  = "var events = [neville, digital,enamoured,  \"\"+\".\"+(\"undertake\",\"aggrieved\",\"commemoration\",\"vacuum\",\"herculean\",\"" ascii
    $s4  = "var denmark=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".fudge4())&&helterskelter[\"c3RhdHVz\".fudge4()] +\"\"==\"MjAw\".fudg" ascii
    $s5  = "heretic = heretic+ events.shift();" fullword ascii
    $s6  = "weasel = ((\"presumptuous\", \"argentina\", \"hitting\", \"jerry\", \"EOxhHVSySk\") + \"uwuChSp\").fudge2();" fullword ascii
    $s7  = "grass = ((\"harboured\", \"fraudulent\", \"appear\", \"lizard\", \"pstBGtnbXVTx\") + \"QbOxemDM\").fudge2();" fullword ascii
    $s8  = "var events = [neville, digital,enamoured,  \"\"+\".\"+(\"undertake\",\"aggrieved\",\"commemoration\",\"vacuum\",\"herculean\",\"" ascii
    $s9  = "String.prototype.fudge2 = function () {" fullword ascii
    $s10 = "String.prototype.fudge = function () {" fullword ascii
    $s11 = "String.prototype.fudge4 = function() {" fullword ascii
    $s12 = "var violation = events.pop().split(\"" fullword ascii
    $s13 = "var recognizable = 6/6;" fullword ascii
    $s14 = "var helterskelter = new stewardess(violation[0]);" fullword ascii
    $s15 = "var avowal = new stewardess(violation[1]);" fullword ascii
    $s16 = "function sensors(simpleton, easel) {" fullword ascii
    $s17 = "nutrition = \"_F2_\";" fullword ascii
    $s18 = "nepal = this;" fullword ascii
    $s19 = "var ephesians = avowal[events.shift()](events.shift());" fullword ascii
    $s20 = "var stewardess = this[events.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}