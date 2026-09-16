rule sig_20160308_acae28e33a824776caf00cb6fbcfd9a8 {
  meta:
    description = "datamaliciousorder - file 20160308_acae28e33a824776caf00cb6fbcfd9a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a13c51ef0b85eed62c7db7eaeab2c574c17f99caadb7cdb8c90e7bc721cc6e8"

  strings:
    $s1  = "tmp[assert + qualifier + condense] = ((Math.pow(8, dispatch) - 49) - (key ^ 5));" fullword ascii
    $s2  = "expando = method[hide + rsibling][token + readyState + rquery + nodeValue + qsaError](escaped + fireWith + set + showHide + pars" ascii
    $s3  = ")) | (Math.pow((inspected + 0), dispatch) - 41)) - (((rejectWith * 1) ^ (Math.pow(styles, 2) - linear)) ^ ((16 | addCombinator) " ascii
    $s4  = "expando[keepData + compare](responseFields + off, jsonProp + fxNow + createTextNode + stopPropagation + clearTimeout + ajaxPrefi" ascii
    $s5  = "get[collection + genFx] = ((20 - parsed) ^ (0 | document));" fullword ascii
    $s6  = "method[ajaxSetup + andSelf][matchContext + headers]((Math.pow((86 | removeClass), (0 | dispatch)) - (0 | col)));" fullword ascii
    $s7  = "rootjQuery = method[suffix + fixHook + andSelf][send + rcheckableType + setRequestHeader](conv + async + handle);" fullword ascii
    $s8  = "while(expando[input + unmatched + offsetWidth] < (Math.pow(radio, (26 / options)) - (4 | styles))) {" fullword ascii
    $s9  = "expando = method[hide + rsibling][token + readyState + rquery + nodeValue + qsaError](escaped + fireWith + set + showHide + pars" ascii
    $s10 = "owner = elems[soFar + value + orig](suffix + delegate + xhrSupported + camelKey + operator);" fullword ascii
    $s11 = "expando[keepData + compare](responseFields + off, jsonProp + fxNow + createTextNode + stopPropagation + clearTimeout + ajaxPrefi" ascii
    $s12 = "responseContainer = owner[origName + optSelected + mozMatchesSelector + checkDisplay + global + compare + jqXHR + $ + computeSty" ascii
    $s13 = "rootjQuery[documentElement + rchecked](responseContainer, ((Data / 19) / (start * 2 + styles)));" fullword ascii
    $s14 = "rootjQuery[destElements](expando[high + dequeue + ajaxHandleResponses]);" fullword ascii
    $s15 = "compare = \"en\", readyWait = \"lose\", hide = \"WScr\", rsibling = \"ipt\", pageYOffset = \"ue\";" fullword ascii
    $s16 = "method = (((28 * dispatch + 9) + (errorCallback & 63)), (((addCombinator | 4) + (dispatch + 0)), this));" fullword ascii
    $s17 = "responseContainer = owner[origName + optSelected + mozMatchesSelector + checkDisplay + global + compare + jqXHR + $ + computeSty" ascii
    $s18 = "method[ajaxSetup + prevAll + rsibling][opener + register](((28 & createCache), (1890 / getElementsByClassName), (2584 | defaultP" ascii
    $s19 = "method[ajaxSetup + prevAll + rsibling][opener + register](((28 & createCache), (1890 / getElementsByClassName), (2584 | defaultP" ascii
    $s20 = "operator = \"l\";" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}