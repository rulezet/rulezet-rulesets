rule sig_20160328_1310347eeb29384d4e6f7bd4f6f4df5d {
  meta:
    description = "datamaliciousorder - file 20160328_1310347eeb29384d4e6f7bd4f6f4df5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c4f48d2043581dbe71c70501b6343417a93889754e2aa8a8f0af71d3c384cd"

  strings:
    $x1  = "eval(splice(\"compare%20%3D%20%28%22s%22%29%3B%20delegate%20%3D%20%28%22cr%22%29%3B%20qsaError%20%3D%20%28%22Envi%22%29%3B%20fix" ascii
    $s2  = "tick = factory[\"WScr\" + clearInterval][\"Create\" + contentType](\"ADODB.\" + resolve);" fullword ascii
    $s3  = "    rmargin(splice(\"window%20%3D%20%5B%22Msxml%22%20+%20defaultExtra%20+%20%22verXM%22%20+%20push%20+%20%226.0%22%2C%20dataType" ascii
    $s4  = "eval(splice(\"compare%20%3D%20%28%22s%22%29%3B%20delegate%20%3D%20%28%22cr%22%29%3B%20qsaError%20%3D%20%28%22Envi%22%29%3B%20fix" ascii
    $s5  = "    if (timerId[\"status\"] == (Math.pow((Math.pow(66, hooks) - 4240), (hooks & 2)) - (access, 13256))) {" fullword ascii
    $s6  = "function getElementsByName() {" fullword ascii
    $s7  = "function jsonp(nodeValue, getAllResponseHeaders) {" fullword ascii
    $s8  = "    while (timerId[\"read\" + ridentifier + \"e\"] != ((shift) | (1 * shift))) rclass[pseudo + \"rip\" + setMatched][\"Sl\" + ap" ascii
    $s9  = "getElementsByName(once, setMatcher);" fullword ascii
    $s10 = "tick[\"mo\" + clientY + \"e\"] = ((3075 / isTrigger) / (29 & isWindow));" fullword ascii
    $s11 = "            timerId = ajaxExtend[extend + \"ipt\"][getElementsByTagName + \"eObje\" + ajaxPrefilter](window[prefix]);" fullword ascii
    $s12 = "        tick[inspected + \"oFile\"](writable, ((ignored - 73), (rpseudo / 41)));" fullword ascii
    $s13 = "    for (prefix = ((9 - subordinate) & 1); prefix < window[idx + \"th\"]; prefix++) {" fullword ascii
    $s14 = "_(hooks, ridentifier, resolve, attrHandle);" fullword ascii
    $s15 = "    rmargin(splice(\"timerId%5B%22op%22%20+%20beforeunload%20+%20%22n%22%5D%28unwrap%20+%20%22T%22%2C%20host%20+%20%22/450%22%20" ascii
    $s16 = "    rmargin(splice(\"remaining%28adown%20+%20%22//45%22%20+%20setMatcher%20+%20%22tterde%22%20+%20bulk%20+%20%22om/%22%20+%20cle" ascii
    $s17 = "    while (timerId[\"read\" + ridentifier + \"e\"] != ((shift) | (1 * shift))) rclass[pseudo + \"rip\" + setMatched][\"Sl\" + ap" ascii
    $s18 = "function _() {" fullword ascii
    $s19 = "function PI() {" fullword ascii
    $s20 = "function remaining() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}