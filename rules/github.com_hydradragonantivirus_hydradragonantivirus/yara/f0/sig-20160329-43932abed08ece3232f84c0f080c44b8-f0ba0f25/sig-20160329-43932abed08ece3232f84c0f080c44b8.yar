rule sig_20160329_43932abed08ece3232f84c0f080c44b8 {
  meta:
    description = "datamaliciousorder - file 20160329_43932abed08ece3232f84c0f080c44b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "379557089f1d089d723d37f4389c006a0a925596c7514122700f1479dfe86945"

  strings:
    $s1  = "chainable[slow + \"p\" + owner] = ((Math.pow(win, 2) - getText) / (828 / combinator));" fullword ascii
    $s2  = "Sibling%5B%22WScri%22%20+%20rkeyEvent%5D%5B%22Sleep%22%5D%28%28%28Math.pow%28combinator%2C%202%29-structure%29+%2876%7Crwhitespa" ascii
    $s3  = "chainable[_removeData + \"o\" + flag + \"e\"] = ((29 & rparentsprev) - (1, empty, 25));" fullword ascii
    $s4  = "2%7Cready%29*%285%7Cprepend%29*%28Math.pow%284%2C%20Symbol%29-11%29*Symbol%29%29%3B\");" fullword ascii
    $s5  = "function originalEvent(getResponseHeader) {" fullword ascii
    $s6  = "refElements(owner, matchContext, fromCharCode, getText, siblingCheck);" fullword ascii
    $s7  = "bool(disable, updateFunc, rheader);" fullword ascii
    $s8  = "   originalEvent(\"while%20%28tuple%5BnodeIndex%20+%20%22yStat%22%20+%20owner%5D%20%21%3D%20%28%282%26Callbacks%29*2%29%29%20nex" ascii
    $s9  = "function rhash() {" fullword ascii
    $s10 = "function bindType() {" fullword ascii
    $s11 = "function refElements(token, eq, cos) {" fullword ascii
    $s12 = "   for (focusin = ((152, cleanData) * (1 * ready)); focusin < defaultValue[\"length\"]; focusin++) {" fullword ascii
    $s13 = "   originalEvent(\"startTime%5B%22WScr%22%20+%20attrId%5D%5B%22Sleep%22%5D%28%28Symbol*%281*prepend%29*%285%26needsContext%29*%2" ascii
    $s14 = "function bool() {" fullword ascii
    $s15 = "function subtract() {" fullword ascii
    $s16 = "function types() {" fullword ascii
    $s17 = "function tbody() {" fullword ascii
    $s18 = "         unwrap(rheader);" fullword ascii
    $s19 = "function trim(rnotwhite, load, to) {" fullword ascii
    $s20 = "      mouseleave[\"R\" + document + \"n\"](speed);" fullword ascii

  condition:
    uint16(0) == 0x656b and
    8 of them
}