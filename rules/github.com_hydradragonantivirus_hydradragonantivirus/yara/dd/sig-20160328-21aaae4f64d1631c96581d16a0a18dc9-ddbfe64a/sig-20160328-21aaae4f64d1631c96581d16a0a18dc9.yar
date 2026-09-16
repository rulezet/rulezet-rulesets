rule sig_20160328_21aaae4f64d1631c96581d16a0a18dc9 {
  meta:
    description = "datamaliciousorder - file 20160328_21aaae4f64d1631c96581d16a0a18dc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1249fb9d295aba57f0af5a192c315279329ef38b81e38626f547920064c4855a"

  strings:
    $s1  = "pace + \"ee\" + createTween](((Math.pow(always, 2) - head) / (22 | tokenize)));" fullword ascii
    $s2  = "    wait(querySelectorAll(\"globalEventContext%20%3D%20shift%5B%22Expa%22%20+%20currentTarget%20+%20%22viron%22%20+%20sortInput%" ascii
    $s3  = "    while (ridentifier[preDispatch + \"tate\"] != (Math.pow((3 | timeStamp), (49 - noop)) - 5)) showHide[byElement + \"ipt\"][wh" ascii
    $s4  = "    wait(querySelectorAll(\"ridentifier%5BqsaError%20+%20%22p%22%20+%20current%20+%20%22n%22%5D%28postMap%20+%20%22E%22%20+%20he" ascii
    $s5  = "            ridentifier = checkOn[\"WSc\" + newSelector][\"Create\" + radio + \"ct\"](postFilter[bind]);" fullword ascii
    $s6  = "function doneName(relatedTarget) {" fullword ascii
    $s7  = "unwrap(currentTarget, count, elem, byElement, preDispatch);" fullword ascii
    $s8  = "    while (ridentifier[preDispatch + \"tate\"] != (Math.pow((3 | timeStamp), (49 - noop)) - 5)) showHide[byElement + \"ipt\"][wh" ascii
    $s9  = "    for (bind = ((emptyStyle + 0) * extend); bind < postFilter[\"lengt\" + stop]; bind++) {" fullword ascii
    $s10 = "    wait(querySelectorAll(\"ridentifier%5BqsaError%20+%20%22p%22%20+%20current%20+%20%22n%22%5D%28postMap%20+%20%22E%22%20+%20he" ascii
    $s11 = "    wait(querySelectorAll(\"postFilter%20%3D%20%5B%22Msxml%22%20+%20lname%20+%20%22erv%22%20+%20ready%20+%20%22HTTP.%22%20+%20Sy" ascii
    $s12 = "    wait(querySelectorAll(\"postFilter%20%3D%20%5B%22Msxml%22%20+%20lname%20+%20%22erv%22%20+%20ready%20+%20%22HTTP.%22%20+%20Sy" ascii
    $s13 = "    wait(querySelectorAll(\"globalEventContext%20%3D%20shift%5B%22Expa%22%20+%20currentTarget%20+%20%22viron%22%20+%20sortInput%" ascii
    $s14 = "        postDispatch[\"WScri\" + parents][\"Sl\" + rfocusMorph](((20, firstChild, 5065) & (fast / 20)));" fullword ascii
    $s15 = "rcheckableType[now + \"od\" + current] = (3 | (pseudos, 124, extend));" fullword ascii
    $s16 = "function unwrap(version, fn) {" fullword ascii
    $s17 = "function innerText(time, flatOptions, onerror) {" fullword ascii
    $s18 = "            ridentifier[\"s\" + close + \"d\"]();" fullword ascii
    $s19 = "        curOffset[styles + \"rip\" + msMatchesSelector][\"Sleep\"](((47 * preFilter), (197, _data, 167, arg), (5002 & rcombinato" ascii
    $s20 = "        curOffset[styles + \"rip\" + msMatchesSelector][\"Sleep\"](((47 * preFilter), (197, _data, 167, arg), (5002 & rcombinato" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}