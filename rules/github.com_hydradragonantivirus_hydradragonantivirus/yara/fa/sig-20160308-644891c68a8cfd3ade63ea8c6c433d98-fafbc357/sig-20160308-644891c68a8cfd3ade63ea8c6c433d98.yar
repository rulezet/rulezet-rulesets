rule sig_20160308_644891c68a8cfd3ade63ea8c6c433d98 {
  meta:
    description = "datamaliciousorder - file 20160308_644891c68a8cfd3ade63ea8c6c433d98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "385db9a30f3d35a3c55250ec1df085587d4503cab387c601275022e1fad9ef02"

  strings:
    $s1  = "colgroup[reject + fontWeight](serializeArray, button + hold + margin + unmatched + fcamelCase + events + responseHeaders + rbugg" ascii
    $s2  = "while (colgroup[match + rbrace] < ((1 + -els) | (4 & getResponseHeader))) {" fullword ascii
    $s3  = "yQSA + ready + jqXHR, !(((((rtypenamespace & 190), (has - 5), (p + 26)) - ((Math.pow(find, 2) - rcombinators) & (11 + uniqueCach" ascii
    $s4  = "combinator = (((1 * lock) ^ (275 / j)), (((15 * border + 11) - (hide ^ 19)), this));" fullword ascii
    $s5  = "colgroup = combinator[attrs + hold][method + Data + now](version + parents + map + th);" fullword ascii
    $s6  = "combinator[rcssNum + overflow][curCSSLeft + expanded + dataTypeOrTransport](((1 + optDisabled) + 11 * sel * 3));" fullword ascii
    $s7  = "v[addGetHookIf + resolveWith + expanded](eased, ((1 + optDisabled) ^ (2 + els)));" fullword ascii
    $s8  = "handleObj[lang + fns + when] = ((25 - returnFalse) * (119, modified, 85, els));" fullword ascii
    $s9  = "getResponseHeader = 7, addGetHookIf = \"sa\", groups = \"m\", method = \"Creat\", guaranteedUnique = \"Expa\", ajaxSettings = \"" ascii
    $s10 = "combinator[rcssNum + overflow][duration]((setPositiveNumber + 3) * (newUnmatched / 7) * (els + 1) * (optDisabled | 5) * (optDisa" ascii
    $s11 = "combinator[rcssNum + overflow][duration]((setPositiveNumber + 3) * (newUnmatched / 7) * (els + 1) * (optDisabled | 5) * (optDisa" ascii
    $s12 = "v = combinator[JSON + cssText + hold][createInputPseudo + insertAfter + doneName](append + collection + rxhtmlTag + checkOn + gr" ascii
    $s13 = "v = combinator[JSON + cssText + hold][createInputPseudo + insertAfter + doneName](append + collection + rxhtmlTag + checkOn + gr" ascii
    $s14 = "colgroup[reject + fontWeight](serializeArray, button + hold + margin + unmatched + fcamelCase + events + responseHeaders + rbugg" ascii
    $s15 = "colgroup[createHTMLDocument + scrollTop + swing]();" fullword ascii
    $s16 = "ist + globalEval + curPosition) + origFn + clientTop + booleans + button + hold + err + matcherFromGroupMatchers;" fullword ascii
    $s17 = "eased = removeEvent[guaranteedUnique + delegateCount + multipleContexts + isSimulated + initialInUnit + async + pixelPosition](l" ascii
    $s18 = "defer = \".She\"," fullword ascii
    $s19 = "version = \"MSXML\";" fullword ascii
    $s20 = "match = \"readys\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}