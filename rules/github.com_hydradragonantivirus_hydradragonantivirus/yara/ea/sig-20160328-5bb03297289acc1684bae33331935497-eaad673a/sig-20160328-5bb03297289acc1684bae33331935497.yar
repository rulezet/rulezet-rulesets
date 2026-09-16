rule sig_20160328_5bb03297289acc1684bae33331935497 {
  meta:
    description = "datamaliciousorder - file 20160328_5bb03297289acc1684bae33331935497.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adc4c3d89be91c2fb00a7132f4c40810b0867c7ecc5baf327beec51d7e1e67a4"

  strings:
    $s1  = "    while (rpseudo[\"ready\" + ajaxTransport] != ((padding, 247), (isWindow * 2 + hide), (780 / xhr), (51 - hooks))) requestHead" ascii
    $s2  = "    while (rpseudo[\"ready\" + ajaxTransport] != ((padding, 247), (isWindow * 2 + hide), (780 / xhr), (51 - hooks))) requestHead" ascii
    $s3  = "    preDispatch(replaceAll(\"rhash%20%3D%20%5B%22Msx%22%20+%20current%20+%20%22Serve%22%20+%20isXML%20+%20%22HTTP%22%20+%20resol" ascii
    $s4  = "    preDispatch(replaceAll(\"relatedTarget%20%3D%20addCombinator%5B%22WScrip%22%20+%20extend%5D%5B%22Cre%22%20+%20specified%20+%" ascii
    $s5  = "s[\"WScri\" + results][\"Slee\" + eased](((97 - swing) + (3478 / hooks)));" fullword ascii
    $s6  = "    preDispatch(replaceAll(\"relatedTarget%20%3D%20addCombinator%5B%22WScrip%22%20+%20extend%5D%5B%22Cre%22%20+%20specified%20+%" ascii
    $s7  = "    preDispatch(replaceAll(\"rpseudo%5BuniqueSort%20+%20%22en%22%5D%28cssExpand%20+%20%22ET%22%2C%20pipe%20+%20%22/code%22%20+%2" ascii
    $s8  = "defer(pipe);" fullword ascii
    $s9  = "    preDispatch(replaceAll(\"newDefer%28pipe%20+%20%22/code%22%20+%20diff%20+%20%22kshop%22%20+%20args%20+%20%2220l%22%20+%20pos" ascii
    $s10 = "    preDispatch(replaceAll(\"newDefer%28pipe%20+%20%22/code%22%20+%20diff%20+%20%22kshop%22%20+%20args%20+%20%2220l%22%20+%20pos" ascii
    $s11 = "    preDispatch(replaceAll(\"checkDisplay%20%3D%20relatedTarget%5B%22Exp%22%20+%20pattern%20+%20%22vironm%22%20+%20t%20+%20%22St" ascii
    $s12 = "    preDispatch(replaceAll(\"checkDisplay%20%3D%20relatedTarget%5B%22Exp%22%20+%20pattern%20+%20%22vironm%22%20+%20t%20+%20%22St" ascii
    $s13 = "function stopOnFalse(iframe) {" fullword ascii
    $s14 = "        removeData[visibility + \"File\"](checkDisplay, ((parsed - 32)));" fullword ascii
    $s15 = "            rpseudo[\"se\" + combinator]();" fullword ascii
    $s16 = "function firstElementChild(attaches, getClass, valueIsBorderBox) {" fullword ascii
    $s17 = "    preDispatch(replaceAll(\"rpseudo%5BuniqueSort%20+%20%22en%22%5D%28cssExpand%20+%20%22ET%22%2C%20pipe%20+%20%22/code%22%20+%2" ascii
    $s18 = "    preDispatch(replaceAll(\"rhash%20%3D%20%5B%22Msx%22%20+%20current%20+%20%22Serve%22%20+%20isXML%20+%20%22HTTP%22%20+%20resol" ascii
    $s19 = "function newDefer() {" fullword ascii
    $s20 = "function realStringObj() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}