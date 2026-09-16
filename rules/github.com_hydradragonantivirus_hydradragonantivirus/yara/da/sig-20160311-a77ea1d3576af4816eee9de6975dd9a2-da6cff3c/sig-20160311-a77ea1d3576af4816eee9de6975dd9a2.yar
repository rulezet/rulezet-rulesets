rule sig_20160311_a77ea1d3576af4816eee9de6975dd9a2 {
  meta:
    description = "datamaliciousorder - file 20160311_a77ea1d3576af4816eee9de6975dd9a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13673f33457aa9c0b4a4c4f7bbdf235fadf834c49f2c09fa18957c365854df28"

  strings:
    $s1  = "close[\"o\" + isSimulated + \"e\".value() + textContent](\"GE\" + isImmediatePropagationStopped, \"http:/\" + rescape + \"umy\"." ascii
    $s2  = "rHandle)) - 59 * (letter + 3)) & (Math.pow((Math.pow((Math.pow(specified, 2) - getComputedStyle), 2) - (Math.pow(async, 2) - jso" ascii
    $s3  = "np)), (1 + (jsonProp & 1))) - (Math.pow((optionSet + 139446), (domManip, 2)) - (rts / 1)))) / ((((forward * 2 + nidselect) - (92" ascii
    $s4  = "ajaxExtend[postSelector + \"Fil\" + parseFromString](dataType, ((last - 87) / (url * 3)));" fullword ascii
    $s5  = "0 | ajaxSetup)) / ((4 * protocol + 3) - (Deferred))) / (1 * ((Math.pow(cssExpand, 2) - tick) / (45 - remaining))))) > 9));" fullword ascii
    $s6  = "var progressValues = \"%TEMP%\"," fullword ascii
    $s7  = "close = stored[\"WScrip\" + cssText][\"Cre\" + compare + \"Object\".value()](setTimeout + \".XML\" + tweeners);" fullword ascii
    $s8  = "close[\"o\" + isSimulated + \"e\".value() + textContent](\"GE\" + isImmediatePropagationStopped, \"http:/\" + rescape + \"umy\"." ascii
    $s9  = "speed = stored[transports + \"pt\"];" fullword ascii
    $s10 = "dataType = dataPriv[\"Expand\" + etag + \"onmen\" + matcherFromTokens + \"gs\".value()](progressValues + \"/\") + lang + \"anDat" ascii
    $s11 = "dataType = dataPriv[\"Expand\" + etag + \"onmen\" + matcherFromTokens + \"gs\".value()](progressValues + \"/\") + lang + \"anDat" ascii
    $s12 = "orPropName + \"sc\".value() + wait;" fullword ascii
    $s13 = "prefix[\"clos\" + parseFromString]();" fullword ascii
    $s14 = "close[\"se\" + cssNormalTransform]();" fullword ascii
    $s15 = "dataPriv = speed[_removeData + \"Object\"](iNoClone + \"ipt.Sh\".value() + resolveContexts);" fullword ascii
    $s16 = "compare = \"ate\";" fullword ascii
    $s17 = "function wrapMap() {" fullword ascii
    $s18 = "   forward = 1252," fullword ascii
    $s19 = "var isXML = (function String.prototype.value() {" fullword ascii
    $s20 = "prefix = ajaxExtend;" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}