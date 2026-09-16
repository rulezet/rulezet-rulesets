rule sig_20160329_2e70762d6e27ae48c6924f34c55825af {
  meta:
    description = "datamaliciousorder - file 20160329_2e70762d6e27ae48c6924f34c55825af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaf3a50134a8039b234ad17724b67e96791eb89c0bda41d4e649610af7a1db48"

  strings:
    $s1  = "seed(\"lname%5BcssNumber%20+%20%22e%22%20+%20replaceAll%5D%28%22GE%22%20+%20i%2C%20%22http%22%20+%20getAttributeNode%20+%20%22ke" ascii
    $s2  = "rbracket[fx + \"ToFil\" + close](cssExpand, ((90 - unqueued) - (Math.pow(21, rreturn) - 411)));" fullword ascii
    $s3  = "if (lname[webkitMatchesSelector + \"atus\"] == ((Math.pow(result, 2) - reject) * (5 | wrap) + (201, beforeSend, 173, tag))) {" fullword ascii
    $s4  = "seed(\"while%20%28lname%5B%22readyS%22%20+%20end%5D%20%21%3D%20%28%28jQuery%261%29*%28computeStyleTests%7C0%29%29%29%20src%5B%22" ascii
    $s5  = "seed(\"lname%5BcssNumber%20+%20%22e%22%20+%20replaceAll%5D%28%22GE%22%20+%20i%2C%20%22http%22%20+%20getAttributeNode%20+%20%22ke" ascii
    $s6  = "for (risSimple = (0 / removeEventListener); risSimple < before[\"l\" + nodeType + \"th\"]; risSimple++) {" fullword ascii
    $s7  = "seed(\"has%5B%22WScrip%22%20+%20clazz%5D%5B%22S%22%20+%20unit%5D%28%28%28Math.pow%28sel%2C%202%29-computeStyleTests%29*%28230%2C" ascii
    $s8  = "seed(\"while%20%28lname%5B%22readyS%22%20+%20end%5D%20%21%3D%20%28%28jQuery%261%29*%28computeStyleTests%7C0%29%29%29%20src%5B%22" ascii
    $s9  = "seed(\"has%5B%22WScrip%22%20+%20clazz%5D%5B%22S%22%20+%20unit%5D%28%28%28Math.pow%28sel%2C%202%29-computeStyleTests%29*%28230%2C" ascii
    $s10 = "seed(\"rbracket%20%3D%20src%5B%22WScri%22%20+%20defaultValue%5D%5B%22Crea%22%20+%20removeAttr%20+%20%22ct%22%5D%28XMLHttpRequest" ascii
    $s11 = "function postSelector(insertBefore, next, fns) {" fullword ascii
    $s12 = "lname[\"s\" + close + \"n\" + setGlobalEval]();" fullword ascii
    $s13 = "rbracket[\"t\" + sibling + \"e\"] = ((jQuery * 1) & jQuery);" fullword ascii
    $s14 = "copy[\"Ru\" + replaceAll](cssExpand);" fullword ascii
    $s15 = "lname = conv[DOMParser + \"ript\"][swing + \"Object\"](before[risSimple]);" fullword ascii
    $s16 = "preDispatch(cssNumber, detach, removeEventListener, rsubmittable);" fullword ascii
    $s17 = "seed(\"push%28detach%20+%20%22/kenny%22%20+%20blur%20+%20%22com/La%22%20+%20parseHTML%20+%20%22.ex%22%20+%20close%29%3B\");" fullword ascii
    $s18 = "seed(\"rbracket%20%3D%20src%5B%22WScri%22%20+%20defaultValue%5D%5B%22Crea%22%20+%20removeAttr%20+%20%22ct%22%5D%28XMLHttpRequest" ascii
    $s19 = "rfocusable(cssNumber, removeEventListener, i, result);" fullword ascii
    $s20 = "unwrap();" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}