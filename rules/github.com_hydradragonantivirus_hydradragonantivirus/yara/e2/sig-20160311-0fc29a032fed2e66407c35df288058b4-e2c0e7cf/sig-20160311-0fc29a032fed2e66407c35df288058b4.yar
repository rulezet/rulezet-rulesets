rule sig_20160311_0fc29a032fed2e66407c35df288058b4 {
  meta:
    description = "datamaliciousorder - file 20160311_0fc29a032fed2e66407c35df288058b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bae2a8703594d4afd8ed16e5bc3c866a341daf9d6ad21a0260f71b9b4f5f3233"

  strings:
    $s1  = "delegateTarget[\"R\" + timeout](elements.exports(((innerText, 229, createTween, 50) + (Math.pow(html, 2) - window))), (1 * rtype" ascii
    $s2  = "minWidth[valueParts + \"pe\".exports() + tmp](\"G\" + special + \"T\", parseHTML + \"p://\".exports() + qualifier + \"rdi\" + pa" ascii
    $s3  = "delegateTarget[\"R\" + timeout](elements.exports(((innerText, 229, createTween, 50) + (Math.pow(html, 2) - window))), (1 * rtype" ascii
    $s4  = "removeData = ((Math.pow((121 - genFx), (20 - hold)) - 1637 * fired * 2 * fired), (3 + (deep & 0)), eval(\"th\" + hash));" fullword ascii
    $s5  = "+ \".com/8\" + push_native, !(fired < (((((2 * fired + 1) | (percent / 15)) & ((deep * 2) + (notifyWith & 5))) + fired * (2 + (t" ascii
    $s6  = "gger / 17))) - (((XMLHttpRequest * 3, (delay / 1), (current + 49)), (indirect + 99) * (deep + 1), ((sortStable | 68) / (preFilte" ascii
    $s7  = "returnValue[\"ty\" + complete + \"e\"] = ((32 - dataType) * (9 / send));" fullword ascii
    $s8  = "testContext[dataAttr + \"Fil\".exports() + letterSpacing](elements, ((30 / reset) - 0));" fullword ascii
    $s9  = "minWidth[valueParts + \"pe\".exports() + tmp](\"G\" + special + \"T\", parseHTML + \"p://\".exports() + qualifier + \"rdi\" + pa" ascii
    $s10 = "delegateTarget = prefix;" fullword ascii
    $s11 = "rs * 3 + deep))) + (((210 + tuples), (1348 - body)) / (71 - udataCur) * (4 - deep))))));" fullword ascii
    $s12 = "width = removeData[\"WScr\".exports() + index];" fullword ascii
    $s13 = "testContext = removeData[triggerHandler + \"ipt\"][opts + \"eObjec\".exports() + risSimple](\"ADODB.\" + winnow + \"m\");" fullword ascii
    $s14 = "prefix = width[\"Create\" + properties + \"t\"](triggerHandler + \"ipt.Sh\".exports() + responseText);" fullword ascii
    $s15 = "minWidth = removeData[\"WScrip\" + risSimple][\"Cre\" + documentElement + \"ect\".exports()](checkClone + \"ML2.X\" + then + \"T" ascii
    $s16 = "elements = prefix[\"Exp\" + b + \"Enviro\" + guaranteedUnique + \"tStri\".exports() + rfocusMorph](\"%TE\" + pseudo) + \"ease\" " ascii
    $s17 = "elements = prefix[\"Exp\" + b + \"Enviro\" + guaranteedUnique + \"tStri\".exports() + rfocusMorph](\"%TE\" + pseudo) + \"ease\" " ascii
    $s18 = "unquoted[\"clo\" + resolveWith]();" fullword ascii
    $s19 = "valueParts = (function String.prototype.exports() {" fullword ascii
    $s20 = "pseudo = \"MP%/\", onreadystatechange = 2214040;" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}