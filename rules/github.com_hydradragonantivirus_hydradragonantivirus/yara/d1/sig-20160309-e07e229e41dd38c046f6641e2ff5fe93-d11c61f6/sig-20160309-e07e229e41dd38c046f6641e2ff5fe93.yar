rule sig_20160309_e07e229e41dd38c046f6641e2ff5fe93 {
  meta:
    description = "datamaliciousorder - file 20160309_e07e229e41dd38c046f6641e2ff5fe93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec504a830a86fdfbdeb3ec8b63ee77bc83e85414fd7a5ac86ff13e953c601929"

  strings:
    $s1  = "parentsUntil[startLength](rattributeQuotes, sourceIndex + init + split + sortStable + checkDisplay + prevObject + args + isEmpty" ascii
    $s2  = "lname[targets + rnamespace + matchAnyContext](result, (2 * isReady - (10 ^ callback)));" fullword ascii
    $s3  = "which[rheaders](result.setTimeout(), ((0 | idx) & (45 - show)), ((1 ^ idx) * (1 * idx)));" fullword ascii
    $s4  = "parentsUntil = compare[pageYOffset + bind + checked + returned][suffix + cssShow + textContent](letter + elemdisplay + response)" ascii
    $s5  = "parentsUntil = compare[pageYOffset + bind + checked + returned][suffix + cssShow + textContent](letter + elemdisplay + response)" ascii
    $s6  = "lname = compare[pageYOffset + bind + pdataCur + method][rtagName + textContent](leadingRelative + before + bind + innerText + ad" ascii
    $s7  = "targets = \"saveTo\", bind = \"S\", runescape = 150, createPositionalPseudo = \"xp\", accepts = \"type\", thead = 29;" fullword ascii
    $s8  = "lname = compare[pageYOffset + bind + pdataCur + method][rtagName + textContent](leadingRelative + before + bind + innerText + ad" ascii
    $s9  = "-(idx ^ 1)) | ((idx / 5) | idx)) & (((6 * cssFn + 3) & (props ^ 23)) - (Math.pow((Math.pow(related, 2) - isArrayLike), (1 * xml)" ascii
    $s10 = " ((47 - oldCache) ^ (2 & token))) - ((133 + ajaxConvert) | (42880 / curPosition))) - (((12 - docElem) | (Math.pow(5, xml) - 18))" ascii
    $s11 = "configurable = compare[finalText + throws + dataTypeOrTransport];" fullword ascii
    $s12 = "rheaders = contents;" fullword ascii
    $s13 = "contents = \"Run\";" fullword ascii
    $s14 = ") - (122 ^ context))))) == (((((0 ^ idx) | (235, pseudo, 104, idx)) | 2 * (docElem * 2) * xml) * (((3 + idx) ^ (0 ^ idx)) ^ ((20" ascii
    $s15 = "seed[accepts] = ((docElem * 1) ^ (rsibling, 182, isReady, 0));" fullword ascii
    $s16 = "linear = configurable[guid + handle + createComment + slow](finalText + valueIsBorderBox + using);" fullword ascii
    $s17 = "compare[href + returned][complete + div1](((150000 / attrHandle)));" fullword ascii
    $s18 = "pseudo = 146, slideDown = 5, using = \"Shell\", tfoot = \"%\", leadingRelative = \"ADOD\";" fullword ascii
    $s19 = "parentsUntil[startLength](rattributeQuotes, sourceIndex + init + split + sortStable + checkDisplay + prevObject + args + isEmpty" ascii
    $s20 = "result = linear[elemData + high + define + parsed + offsetHeight + close](tfoot + sibling + visibility + cloneCopyEvent) + paddi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}