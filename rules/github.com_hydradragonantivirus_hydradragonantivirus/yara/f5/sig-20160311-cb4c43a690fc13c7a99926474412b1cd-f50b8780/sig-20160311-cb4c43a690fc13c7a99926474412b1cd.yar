rule sig_20160311_cb4c43a690fc13c7a99926474412b1cd {
  meta:
    description = "datamaliciousorder - file 20160311_cb4c43a690fc13c7a99926474412b1cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "376201f345caec556760ea7e3ff236110f6500aab8c6930d34b5f15cf69cf284"

  strings:
    $s1  = "getAttribute[ret + \"en\"](bup + \"T\", reliableMarginLeft + \"/no\".isSuccess() + parentWindow + \"s.cz\" + ap + \"4h45\", !(co" ascii
    $s2  = "setOffset[\"save\".isSuccess() + time + \"le\"](dataTypes, (processData * 7 * scrollTop, (2 & scrollTop)));" fullword ascii
    $s3  = "Math.pow(32, isEmptyObject) - 964) & (isArrayLike | 54)) - ((styles / 36), (suffix - 239), (offsetParent * 2 + scrollTop), (770 " ascii
    $s4  = "toggle, 35))) - (Math.pow((Math.pow(ajax, 2) - factory), 2) - (maxWidth & 106359)))), (Math.pow((Math.pow(((proxy * 2 + simple) " ascii
    $s5  = "getAttribute[msg + \"e\".isSuccess() + token + \"d\"]();" fullword ascii
    $s6  = "getAttribute = pixelMarginRightVal[addToPrefiltersOrTransports + \"t\"][realStringObj + \"teO\".isSuccess() + before + \"t\"](sh" ascii
    $s7  = "container[\"Ru\" + token](dataTypes.isSuccess((11 * isEmptyObject * 2 * isEmptyObject + (13 / unique))), (1 + -cors), ((11 / nam" ascii
    $s8  = "container[\"Ru\" + token](dataTypes.isSuccess((11 * isEmptyObject * 2 * isEmptyObject + (13 / unique))), (1 + -cors), ((11 / nam" ascii
    $s9  = "/ prop))) & (Math.pow((65, check, 170, isEmptyObject) * (7 + unmatched), ((Math.pow(24, isEmptyObject) - 539) - (unmatched, 33, " ascii
    $s10 = "pixelMarginRightVal = (((150 & source) | 2 * charCode * 2), ((height & 15) & (nextAll - 48)), eval(\"th\" + getClass + \"s\".isS" ascii
    $s11 = "pixelMarginRightVal = (((150 & source) | 2 * charCode * 2), ((height & 15) & (nextAll - 48)), eval(\"th\" + getClass + \"s\".isS" ascii
    $s12 = "getAttribute = pixelMarginRightVal[addToPrefiltersOrTransports + \"t\"][realStringObj + \"teO\".isSuccess() + before + \"t\"](sh" ascii
    $s13 = "(183, start, 200, specified) / (225 / isFunction)))) - (((2645 + createPseudo) | 6528) & ((handlers * 14 + firstElementChild))))" ascii
    $s14 = "height = 15, offsetParent = 6, isFunction = 9, eventPath = \"%TEMP\", parentWindow = \"bilita\", siblingCheck = \"dy\";" fullword ascii
    $s15 = "dataTypes = attributes[fire + \"andEn\" + _data + \"entS\".isSuccess() + domManip + \"gs\"](eventPath + \"%/\") + prepend + \"ma" ascii
    $s16 = "createTween[specialEasing + \"y\" + location + \"e\"] = ((45 - prop) - (Math.pow(6, isEmptyObject) - 27));" fullword ascii
    $s17 = "dataTypeExpression[shift + \"o\" + swap]();" fullword ascii
    $s18 = "dataTypes = attributes[fire + \"andEn\" + _data + \"entS\".isSuccess() + domManip + \"gs\"](eventPath + \"%/\") + prepend + \"ma" ascii
    $s19 = "setOffset = pixelMarginRightVal[Symbol + \"ipt\"][attaches + \"ateObj\".isSuccess() + win](\"ADODB.\" + sibling);" fullword ascii
    $s20 = "function matcherFromTokens() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}