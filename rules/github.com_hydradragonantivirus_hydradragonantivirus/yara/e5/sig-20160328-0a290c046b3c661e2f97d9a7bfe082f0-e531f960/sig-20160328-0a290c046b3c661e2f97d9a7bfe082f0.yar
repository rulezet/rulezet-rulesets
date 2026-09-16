rule sig_20160328_0a290c046b3c661e2f97d9a7bfe082f0 {
  meta:
    description = "datamaliciousorder - file 20160328_0a290c046b3c661e2f97d9a7bfe082f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2960db32357b766df6b1a3c161ae5838a86e1ccc0869adf5552e2e7dedafafbc"

  strings:
    $x1  = "eval(subordinate(\"divStyle%20%3D%20%28%22%3A//the%22%29%2C%20type%20%3D%20%287148%29%2C%20offsetParent%20%3D%20%28%22.%22%29%2C" ascii
    $s2  = "lemdisplay, 4))) module[\"WSc\" + rnoContent][\"Slee\" + webkitMatchesSelector](((Math.pow(dataTypes, 2) - options) & (84, unwra" ascii
    $s3  = "while (classNames[not + \"Sta\" + th] != ((pageX / 34), (padding * 2 * padding * 2 * run), (3 * padding + 1), (createCache, 122," ascii
    $s4  = "postFinder[\"WSc\" + rnoContent][\"Sl\" + toggle](((active | 640) | (triggerHandler & 920)));" fullword ascii
    $s5  = "newSelector[clearCloneStyle + \"yp\" + binary] = ((127, dest) - (24 & Sizzle));" fullword ascii
    $s6  = "if (classNames[\"sta\" + pointerleave + \"s\"] == ((Math.pow(actualDisplay, 2) - cssHooks) & (Math.pow(111, padding) - 12115))) " ascii
    $s7  = "newSelector[\"mo\" + wait + \"e\"] = ((1 * run) & (3 & run));" fullword ascii
    $s8  = "clearTimeout(subordinate(\"caption%20%3D%20%5BeventDoc%20+%20%22ml2.%22%20+%20sortOrder%20+%20%22verXML%22%20+%20pointerenter%20" ascii
    $s9  = "function mappedTypes(scripts, appendChild) {" fullword ascii
    $s10 = "clearTimeout(subordinate(\"style%28%22htt%22%20+%20removeData%20+%20%22ebikem%22%20+%20keepScripts%20+%20%22lace%22%20+%20td%20+" ascii
    $s11 = "clearTimeout(subordinate(\"style%28%22htt%22%20+%20removeData%20+%20%22ebikem%22%20+%20keepScripts%20+%20%22lace%22%20+%20td%20+" ascii
    $s12 = "function postMap(random, t) {" fullword ascii
    $s13 = "for (using = ((127 * padding), (1 * postSelector)); using < caption[prev + \"gth\"]; using++) {" fullword ascii
    $s14 = "oldCallbacks[mouseenter + \"ipt\"][specified](((easing - 3822) | (type & 6043)));" fullword ascii
    $s15 = "while (classNames[not + \"Sta\" + th] != ((pageX / 34), (padding * 2 * padding * 2 * run), (3 * padding + 1), (createCache, 122," ascii
    $s16 = "classNames = module[mouseenter + \"ipt\"][rcomma + \"eObje\" + charCode](caption[using]);" fullword ascii
    $s17 = "function subordinate(rootjQuery) {" fullword ascii
    $s18 = "clearTimeout(subordinate(\"classNames%5B%22op%22%20+%20setOffset%5D%28%22GE%22%20+%20prevUntil%2C%20%22http%22%20+%20divStyle%20" ascii
    $s19 = "oldCallbacks = module = postFinder = mozMatchesSelector = vendorPropName.collection();" fullword ascii
    $s20 = "postMap(callbackName, value, addGetHookIf, postSelector, clearCloneStyle);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}