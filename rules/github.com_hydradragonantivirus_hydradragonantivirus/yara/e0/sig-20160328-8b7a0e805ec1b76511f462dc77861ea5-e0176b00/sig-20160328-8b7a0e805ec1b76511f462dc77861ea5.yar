rule sig_20160328_8b7a0e805ec1b76511f462dc77861ea5 {
  meta:
    description = "datamaliciousorder - file 20160328_8b7a0e805ec1b76511f462dc77861ea5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42137caf41466e66bfeb74ceb931c9f8bae93b07434a8dba2e144e3c34b57cf7"

  strings:
    $s1  = "getWindow(markFunction(\"fixHook%5B%22o%22%20+%20postSelector%20+%20%22e%22%20+%20src%5D%28%22G%22%20+%20postFinder%20+%20%22T%2" ascii
    $s2  = "eval(markFunction(\"version%20%3D%20%28%22/zWbD_%22%29%3Bvar%20hide%20%3D%20%28%22len%22%29%2C%20dataAndEvents%20%3D%20%28%222.X" ascii
    $s3  = "getWindow(markFunction(\"compile%20%3D%20first%5B%22Exp%22%20+%20getById%20+%20%22iron%22%20+%20oMatchesSelector%20+%20%22rin%22" ascii
    $s4  = "transports[\"Save\" + off + \"le\"](compile, ((condense & 3) & (test - 53)));" fullword ascii
    $s5  = "dataAttr[responseText + \"rip\" + createButtonPseudo][\"Sleep\"]((Math.pow((traditional & 3838), (blur / 30)) - (nodeNameSelecto" ascii
    $s6  = "dataAttr[responseText + \"rip\" + createButtonPseudo][\"Sleep\"]((Math.pow((traditional & 3838), (blur / 30)) - (nodeNameSelecto" ascii
    $s7  = "while (fixHook[\"read\" + pageX + \"ate\"] != ((Math.pow(sibling, 2) - cacheLength) - (Math.pow(23, condense) - 497))) cssNormal" ascii
    $s8  = "22F.exe%22%2C%20%21%28%28%283%7CnextUntil%29*%281*condense%29%29%20%3D%3D%20%28%28141%2CnextUntil%29+3%29%29%29%3B\"));" fullword ascii
    $s9  = "while (fixHook[\"read\" + pageX + \"ate\"] != ((Math.pow(sibling, 2) - cacheLength) - (Math.pow(23, condense) - 497))) cssNormal" ascii
    $s10 = "sform[unwrap + \"ipt\"][startLength](((isBorderBox | 11) + (t - 89)));" fullword ascii
    $s11 = "getWindow(markFunction(\"compile%20%3D%20first%5B%22Exp%22%20+%20getById%20+%20%22iron%22%20+%20oMatchesSelector%20+%20%22rin%22" ascii
    $s12 = "bind(responseText, postSelector, getWindow);" fullword ascii
    $s13 = "first[rmargin + \"n\"](compile);" fullword ascii
    $s14 = "getWindow(markFunction(\"first%20%3D%20string%5B%22WScr%22%20+%20eventPath%5D%5B%22Cre%22%20+%20rfocusMorph%20+%20%22bje%22%20+%" ascii
    $s15 = "getWindow(markFunction(\"first%20%3D%20string%5B%22WScr%22%20+%20eventPath%5D%5B%22Cre%22%20+%20rfocusMorph%20+%20%22bje%22%20+%" ascii
    $s16 = "for (send = ((4 + memory) - (85 - settings)); send < newCache[hide + \"gth\"]; send++) {" fullword ascii
    $s17 = "function bind() {" fullword ascii
    $s18 = "offsetHeight(destElements, off, ready, original);" fullword ascii
    $s19 = "eval(markFunction(\"version%20%3D%20%28%22/zWbD_%22%29%3Bvar%20hide%20%3D%20%28%22len%22%29%2C%20dataAndEvents%20%3D%20%28%222.X" ascii
    $s20 = "cached(rtypenamespace, postFinder, unwrap, checkNonElements, leadingRelative);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}