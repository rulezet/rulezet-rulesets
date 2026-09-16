rule sig_20160325_f8a26816db877fce3d8d48a2b09af5c9 {
  meta:
    description = "datamaliciousorder - file 20160325_f8a26816db877fce3d8d48a2b09af5c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b88658a9aa56c2ff97a64834d6fcee173cadf40f7d175f7da4a8454cb6891f44"

  strings:
    $s1  = "  return once[getScript](access, valueIsBorderBox);" fullword ascii
    $s2  = "function tfoot(access, once, valueIsBorderBox, getScript) {" fullword ascii
    $s3  = "radioValue[p](((832 | exports) + (1608 * string + 946)));" fullword ascii
    $s4  = "function content() {" fullword ascii
    $s5  = "  checkContext[Deferred + \"p\" + safeActiveElement] = (l + 0);" fullword ascii
    $s6  = "  delay[\"WScri\" + grep][\"Slee\" + split](((prototype, 2845) + (show + 1467)));" fullword ascii
    $s7  = "subordinate = radioValue[\"Create\" + border](\"WSc\" + nodeNameSelector + \".Shel\" + module);" fullword ascii
    $s8  = "radioValue = delay[\"WScrip\" + createDocumentFragment];" fullword ascii
    $s9  = "tick = subordinate[\"Exp\" + implementation + \"ironme\" + stateVal + \"ing\" + rnamespace](\"%TE\" + sort) + \"addB\" + rnoInne" ascii
    $s10 = "tick = subordinate[\"Exp\" + implementation + \"ironme\" + stateVal + \"ing\" + rnamespace](\"%TE\" + sort) + \"addB\" + rnoInne" ascii
    $s11 = "    var getBoundingClientRect = [][\"cons\" + properties + \"or\"][opts + \"otype\"][rnamespace + \"o\" + createButtonPseudo][\"" ascii
    $s12 = "  checkContext = new delay[\"Acti\" + one + \"bje\" + createOptions](\"ADO\" + sortInput + \"eam\");" fullword ascii
    $s13 = "function matcherFromTokens() {" fullword ascii
    $s14 = "  setup(readyWait, using, matchExpr, startTime);" fullword ascii
    $s15 = "  matcherFromTokens(related);" fullword ascii
    $s16 = "function rCRLF(ajaxExtend, rnoContent, once, elementMatchers) {" fullword ascii
    $s17 = "content(p, classNames);" fullword ascii
    $s18 = "function box() {" fullword ascii
    $s19 = "function ontype() {" fullword ascii
    $s20 = "function options() {" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}