rule sig_20160311_9068336b273f392c0a9643df15739137 {
  meta:
    description = "datamaliciousorder - file 20160311_9068336b273f392c0a9643df15739137.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d505da46d2a126c6090203970a925b109fe4ff993d5b6e95191f5ac0aa802b67"

  strings:
    $s1  = "hasScripts[trim + \"en\"](hasClass + \"T\", ignored + \"//pe\".holdReady() + inPage + \"dicke\" + createInputPseudo + \"om/877\"" ascii
    $s2  = "e, !(2 < ((((pop - 4) + (Math.pow(fns, 2) - getJSON)) - ((Math.pow(34, eased) - 1116) + (pop | 8))) * (((token | 163), (cur + 0)" ascii
    $s3  = "hasContent = addCombinator[\"Creat\" + handler + \"ct\".holdReady()](focus + \"pt.She\" + Callbacks);" fullword ascii
    $s4  = "hasScripts = currentValue[\"WScrip\" + hidden][\"Create\".holdReady() + beforeSend + \"ct\"](marginDiv + \".XML\" + statusCode +" ascii
    $s5  = "hasScripts = currentValue[\"WScrip\" + hidden][\"Create\".holdReady() + beforeSend + \"ct\"](marginDiv + \".XML\" + statusCode +" ascii
    $s6  = "disableScript[\"R\" + scale](stop.holdReady((Math.pow((valueParts - 122), eased) - (507 * matchedCount + 263))), ((cur & 1) & (a" ascii
    $s7  = "disableScript[\"R\" + scale](stop.holdReady((Math.pow((valueParts - 122), eased) - (507 * matchedCount + 263))), ((cur & 1) & (a" ascii
    $s8  = "stop = hasContent[\"Expand\" + docElem + \"nmen\".holdReady() + pointerleave + \"ings\"](j + \"/\") + setMatched + \"rs\".holdRe" ascii
    $s9  = "stop = hasContent[\"Expand\" + docElem + \"nmen\".holdReady() + pointerleave + \"ings\"](j + \"/\") + setMatched + \"rs\".holdRe" ascii
    $s10 = "j = \"%TEMP%\";" fullword ascii
    $s11 = "0))) - (((Math.pow(implicitRelative, 2) - overflowY), (5 * leadingRelative + 1)) + (attrHooks | (84 - click)))))));" fullword ascii
    $s12 = ") + (cur + (1 + -cur))) * (((267960 / blur) / (231 / leadingRelative)), (1 + (cur + 0))) * ((Math.pow(eased * 3 * eased * 2, eas" ascii
    $s13 = "trim = \"op\", relatedTarget = \"n\";" fullword ascii
    $s14 = "ed) - (39, active, 538)) - ((minWidth, 22, sourceIndex, 96) - (base & 62))) * (((cur + 0) * (hold - 35)) & (eased | (1 + -cur)))" ascii
    $s15 = "pseudos[\"saveTo\".holdReady() + detach + \"e\"](stop, 2);" fullword ascii
    $s16 = "currentValue = ((7 - eased) * (54 - click), ((4 | cur) & (25 / rclickable)), eval(\"t\" + escapedWhitespace + \"i\".holdReady() " ascii
    $s17 = "pseudos = currentValue[focus + \"pt\"][createButtonPseudo + \"eObjec\".holdReady() + hidden](\"ADODB.\" + last);" fullword ascii
    $s18 = "currentValue = ((7 - eased) * (54 - click), ((4 | cur) & (25 / rclickable)), eval(\"t\" + escapedWhitespace + \"i\".holdReady() " ascii
    $s19 = "hasScripts[trim + \"en\"](hasClass + \"T\", ignored + \"//pe\".holdReady() + inPage + \"dicke\" + createInputPseudo + \"om/877\"" ascii
    $s20 = "content();" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}