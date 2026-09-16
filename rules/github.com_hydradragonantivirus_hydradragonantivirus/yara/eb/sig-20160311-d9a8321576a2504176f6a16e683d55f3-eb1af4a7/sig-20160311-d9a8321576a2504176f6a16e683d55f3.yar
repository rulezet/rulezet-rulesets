rule sig_20160311_d9a8321576a2504176f6a16e683d55f3 {
  meta:
    description = "datamaliciousorder - file 20160311_d9a8321576a2504176f6a16e683d55f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e6a96df7889292590ce0cd511f680c8fd113c28619247555873ce60f51757f5"

  strings:
    $s1  = "replaceWith[\"op\" + pixelMarginRight](\"GE\" + serializeArray, \"http:/\".round() + code + \".211.\" + curElem + \"dd0\" + when" ascii
    $s2  = " (2 | (focus / 44)))), (((hasContent + (64 | getResponseHeader)) - ((49 + find) - 2 * l * 3)), (find * (Math.pow(8, l) - 53) * (" ascii
    $s3  = "events[simple + \"ToF\".round() + complete](setPositiveNumber, (l | (1 + -hasContent)));" fullword ascii
    $s4  = "elem[originalOptions + \"un\"](setPositiveNumber.round(((scrollTop + 40) & (Math.pow(elems, 2) - uid))), ((39 + has), (69 & bool" ascii
    $s5  = "rneedsContext / 31) - ((hasContent * 18) * l * 5 + (focus | 10)))), ((((focus | 1) + (focus / 47)) + (focus / 26)) * ((display, " ascii
    $s6  = "ns), (25 - doneName)), ((2 + owner) - (18 + support)));" fullword ascii
    $s7  = "\".round(), !(8 == (((((computeStyleTests / 19), (hasContent + 0)) + (hasContent + (1 * focus))) | ((3 * newCache, (243, anim)) " ascii
    $s8  = "replaceWith[\"op\" + pixelMarginRight](\"GE\" + serializeArray, \"http:/\".round() + code + \".211.\" + curElem + \"dd0\" + when" ascii
    $s9  = "function rheader() {" fullword ascii
    $s10 = "replaceWith = origType[\"WSc\".round() + flag][\"Create\" + progressValues + \"ect\"](attachEvent + \".XMLHT\".round() + file);" fullword ascii
    $s11 = "2) + ((lock, 19, l) * 3))))));" fullword ascii
    $s12 = "url = origType[\"WSc\" + flag];" fullword ascii
    $s13 = "args[\"t\" + context + \"e\"] = ((focus | 1));" fullword ascii
    $s14 = "replaceWith[list + \"nd\"]();" fullword ascii
    $s15 = "computeStyleTests = 361, owner = (function Object.prototype.round() {" fullword ascii
    $s16 = "curElem = \"199/h\", support = 22, slideDown = \"iron\";" fullword ascii
    $s17 = "complete = \"ile\";" fullword ascii
    $s18 = "function ajaxHandleResponses() {" fullword ascii
    $s19 = "function options() {" fullword ascii
    $s20 = "attrId = \".\", speeds = \"%TE\", acceptData = \"write\", attachEvent = \"MSXML2\", split = 74, href = \"DB.\";" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}