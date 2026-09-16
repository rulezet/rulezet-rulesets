rule sig_20160311_27c52ac2ac2b67dba7304731fafa05f2 {
  meta:
    description = "datamaliciousorder - file 20160311_27c52ac2ac2b67dba7304731fafa05f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0a5c507fd861134e2206b3e375de3e1baf6b79ebe6abd96659fea2aabf74e20"

  strings:
    $x1  = "disableScript[promise + \"p\" + getClientRects + \"n\".innerText()](parsed + \"ET\", nidselect + \"://\" + show + \"msta\".inner" ascii
    $s2  = "disableScript = boxSizingReliableVal[\"WSc\".innerText() + fire + \"t\"][completed + \"Objec\" + lang](\"MSXML\".innerText() + c" ascii
    $s3  = "disableScript = boxSizingReliableVal[\"WSc\".innerText() + fire + \"t\"][completed + \"Objec\" + lang](\"MSXML\".innerText() + c" ascii
    $s4  = "disableScript[promise + \"p\" + getClientRects + \"n\".innerText()](parsed + \"ET\", nidselect + \"://\" + show + \"msta\".inner" ascii
    $s5  = "opener = fcamelCase[\"Expa\" + rattributeQuotes + \"nvi\".innerText() + matches + \"ntStri\" + owner](\"%TEMP%\" + tokenCache) +" ascii
    $s6  = "opener = fcamelCase[\"Expa\" + rattributeQuotes + \"nvi\".innerText() + matches + \"ntStri\" + owner](\"%TEMP%\" + tokenCache) +" ascii
    $s7  = "qsaError = \"l\", padding = \"v.com\", computed = \"is\", tabIndex = 6, parsed = \"G\", fire = \"rip\";" fullword ascii
    $s8  = "disableScript[proxy + \"nd\".innerText()]();" fullword ascii
    $s9  = "amd[attrNames + \"p\".innerText() + getClientRects] = ((182, nonce, 170, box) / (8 * tabIndex + 2));" fullword ascii
    $s10 = "r) * (2 & ajaxConvert) / (3 * selector * 2 * on * 2 * on / (18 + rrun))) * ((2 * computeStyleTests * 3 / (conv2 / 27)) | ((remov" ascii
    $s11 = "return relatedTarget" fullword ascii
    $s12 = "var relatedTarget = this;" fullword ascii
    $s13 = "0600 / parseJSON) / (78 - animated)))))));" fullword ascii
    $s14 = "replaceChild[matcherOut + \"un\"](opener.innerText(((Deferred & 253) - (delegate - 121))), ((load & 1) & (load * 0)), hooks);" fullword ascii
    $s15 = "Sizzle = boxSizingReliableVal[nodeValue + \"t\"][completed + \"Obje\" + actualDisplay](\"ADOD\".innerText() + completeDeferred +" ascii
    $s16 = "Sizzle = boxSizingReliableVal[nodeValue + \"t\"][completed + \"Obje\" + actualDisplay](\"ADOD\".innerText() + completeDeferred +" ascii
    $s17 = "Sizzle[ownerDocument + \"en\"]();" fullword ascii
    $s18 = "Sizzle[num + \"oFi\" + prop](opener, (on & 3));" fullword ascii
    $s19 = "nnerText() + createElement + \"ts\" + setAttribute + \"sc\" + body;" fullword ascii
    $s20 = "proxy = \"se\";" fullword ascii

  condition:
    uint16(0) == 0x776f and
    1 of ($x*) and 4 of them
}