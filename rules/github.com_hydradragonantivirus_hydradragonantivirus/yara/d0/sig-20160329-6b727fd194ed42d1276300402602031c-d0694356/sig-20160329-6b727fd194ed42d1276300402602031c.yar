rule sig_20160329_6b727fd194ed42d1276300402602031c {
  meta:
    description = "datamaliciousorder - file 20160329_6b727fd194ed42d1276300402602031c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5f4873c6c972c94be92dd916f9c19040790127b9bb77a872ebd21b08b864ee"

  strings:
    $s1  = "function targets(replaceAll, onreadystatechange) {" fullword ascii
    $s2  = "visibility(\"attrNames%20%3D%20addEventListener%5B%22WScr%22%20+%20fail%5D%5B%22Create%22%20+%20compareDocumentPosition%20+%20%2" ascii
    $s3  = "visibility(\"attrNames%20%3D%20addEventListener%5B%22WScr%22%20+%20fail%5D%5B%22Create%22%20+%20compareDocumentPosition%20+%20%2" ascii
    $s4  = "visibility(\"superMatcher%20%3D%20doc%5B%22WScr%22%20+%20fail%5D%5B%22Creat%22%20+%20func%20+%20%22ct%22%5D%28responseHeaders%20" ascii
    $s5  = "inspected[curTop + \"ipt\"][mouseHooks](((gotoEnd * 5 * when) - (6297 - parents)));" fullword ascii
    $s6  = "visibility(\"setDocument%5Bmouseenter%20+%20%22pe%22%20+%20td%5D%28%22G%22%20+%20grep%2C%20%22htt%22%20+%20rpseudo%20+%20%22/sta" ascii
    $s7  = "visibility(\"superMatcher%20%3D%20doc%5B%22WScr%22%20+%20fail%5D%5B%22Creat%22%20+%20func%20+%20%22ct%22%5D%28responseHeaders%20" ascii
    $s8  = "visibility(\"inspected%5B%22WScr%22%20+%20fail%5D%5B%22Sl%22%20+%20responseHeadersString%5D%28%28%28r20%29*2*%28fxNow%29*%285%26" ascii
    $s9  = "visibility(\"inspected%5B%22WScr%22%20+%20fail%5D%5B%22Sl%22%20+%20responseHeadersString%5D%28%28%28r20%29*2*%28fxNow%29*%285%26" ascii
    $s10 = "function stopImmediatePropagation(scripts) {" fullword ascii
    $s11 = "attrNames[unmatched](setDocument[\"respo\" + rreturn + \"ody\"]);" fullword ascii
    $s12 = "has(clone, inspectPrefiltersOrTransports);" fullword ascii
    $s13 = "visibility(\"while%20%28setDocument%5B%22read%22%20+%20rnotwhite%5D%20%21%3D%20%28method*%284%7Cidx%29%29%29%20doc%5B%22WScrip%2" ascii
    $s14 = "visibility(\"stateVal%20%3D%20%5Bshow%20+%20%22l2.%22%20+%20tmp%20+%20%22erX%22%20+%20extra%20+%20%22TP.6.%22%20+%20maxIteration" ascii
    $s15 = "visibility(\"while%20%28setDocument%5B%22read%22%20+%20rnotwhite%5D%20%21%3D%20%28method*%284%7Cidx%29%29%29%20doc%5B%22WScrip%2" ascii
    $s16 = "visibility(\"stateVal%20%3D%20%5Bshow%20+%20%22l2.%22%20+%20tmp%20+%20%22erX%22%20+%20extra%20+%20%22TP.6.%22%20+%20maxIteration" ascii
    $s17 = "checkClone(parts, inspectPrefiltersOrTransports, idx, clazz, method);" fullword ascii
    $s18 = "function undelegate() {" fullword ascii
    $s19 = "function match() {" fullword ascii
    $s20 = "duration();" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}