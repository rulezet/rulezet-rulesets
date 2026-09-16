rule sig_20160307_eed09c2aad89b3c4b16992403f4f21f0 {
  meta:
    description = "datamaliciousorder - file 20160307_eed09c2aad89b3c4b16992403f4f21f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae12417e11b68daa3067a642c92a7b4b290a441061738581be503ec5e25008b4"

  strings:
    $x1  = "reject[_queueHooks](guaranteedUnique, contentDocument + inArray + rejectWith + container + errorCallback + callback + curCSSTop " ascii
    $s2  = "compile = getJSON[module + stored + clientY + selection + radioValue + parts](overwritten + forward + matches) + lang + styles +" ascii
    $s3  = "compile = getJSON[module + stored + clientY + selection + radioValue + parts](overwritten + forward + matches) + lang + styles +" ascii
    $s4  = "s + -1) / (reverse + 2)) | ((subtract ^ 3) + settings * 2)))) == (((settings * 3 / ((hasScripts) / (8 + fragment))) & (1 * onlyH" ascii
    $s5  = "dirrunsUnique = createOptions[close + removeEvent][extra + pageXOffset + ignored](modified + tr + getter);" fullword ascii
    $s6  = "se), (1 ^ settings)) - (1259 - load))) & (((82 - scale) / (40 ^ password)) + 0)))));" fullword ascii
    $s7  = "   dirrunsUnique[step + types + nextAll](reject[relatedTarget + rquickExpr + sourceIndex + responseText]);" fullword ascii
    $s8  = "createOptions = (((222 & attrHooks), (40, pushStack, 137, subordinate), (368 - tokens), 193), ((siblingCheck | (2 ^ inspected))," ascii
    $s9  = "andlers)) & (((Math.pow((26 & reverse), (2 & siblingCheck)) - 5 * siblingCheck * 29) / (Math.pow((Math.pow(props, 2) - stopOnFal" ascii
    $s10 = "createOptions = (((222 & attrHooks), (40, pushStack, 137, subordinate), (368 - tokens), 193), ((siblingCheck | (2 ^ inspected))," ascii
    $s11 = "   remaining[camelKey](compile.defaultView(), (onlyHandlers * (0 | newContext)), ((47 - get) / (7 & expanded)));" fullword ascii
    $s12 = " createPseudo + getAll + attachEvent + before + MAX_NEGATIVE;" fullword ascii
    $s13 = "   createOptions[rmargin + remove + rinputs][propFilter]((Math.pow(settings, 2) - wrapAll) * (106, hasData, 64, siblingCheck) * " ascii
    $s14 = " - ((string - 65) ^ (getElementsByName ^ 229)))) + (((onlyHandlers + -1) / ((removeClass - 28) | (empty - 12))) / (((onlyHandler" ascii
    $s15 = "+ image + mapped + chainable + crossDomain, !((((((1 * pseudo) - (34 | unloadHandler)) & ((1 * opener) + (0 ^ onlyHandlers))) - " ascii
    $s16 = "remove = \"cr\", fontWeight = \"eObjec\", setRequestHeader = \"Run\", opener = 30;" fullword ascii
    $s17 = "while(reject[types + results + outermost + nativeStatusText + handleObjIn] < (siblingCheck * 19 - (animate ^ 51))) {" fullword ascii
    $s18 = "createOptions[prop + add][propFilter](((all - 4875) + (newContext | 6380)));" fullword ascii
    $s19 = "reject[_queueHooks](guaranteedUnique, contentDocument + inArray + rejectWith + container + errorCallback + callback + curCSSTop " ascii
    $s20 = "urlAnchor = \"Crea\", types = \"r\", rquickExpr = \"ons\", nativeStatusText = \"ta\", password = 25, el = \"oFile\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}