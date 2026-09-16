rule sig_20160308_4f741c5587293fb33c17534917e04987 {
  meta:
    description = "datamaliciousorder - file 20160308_4f741c5587293fb33c17534917e04987.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c11356bb5aacc7dad6ca253af6be4bd0cbbc1073eae03e7c5620a3fc4380b54"

  strings:
    $x1  = "parts[filter + isPlainObject](contexts, pointerleave + jsonProp + to + noop + targets + rscriptType + contains + throws + dataTy" ascii
    $s2  = "parts[filter + isPlainObject](contexts, pointerleave + jsonProp + to + noop + targets + rscriptType + contains + throws + dataTy" ascii
    $s3  = "(triggered + 0)))) | ((((prepend * 8) | (state / 13)) + (triggered * 7) * prepend) - ((23 - (src ^ 7)) | (Math.pow((contents + 1" ascii
    $s4  = "password = uid[linear + compareDocumentPosition];" fullword ascii
    $s5  = "postMap[params](getJSON.shift(), ((triggered * 1) + -triggered), (1 + -triggered));" fullword ascii
    $s6  = "unquoted[eased + getBoundingClientRect](getJSON, ((delay & 2) | (triggered + -1)));" fullword ascii
    $s7  = "option[progressContexts + actualDisplay + getById] = ((emptyStyle - 10) * (triggered * 0));" fullword ascii
    $s8  = "step = \"ready\", mouseenter = \"WScrip\", targets = \"ri.p\";" fullword ascii
    $s9  = "DOMParser = password[duration + func + _jQuery + opts + udataOld](mouseenter + r20 + uniqueID);" fullword ascii
    $s10 = "pes + push_native + rclickable, !(((((3 ^ access) ^ (4 + delay)) & (((78 ^ off) + (Math.pow(19, prepend) - 341)), ((anim | 6) + " ascii
    $s11 = "0), (triggered * 2)) - (Math.pow(adown, 2) - init))))) == 6));" fullword ascii
    $s12 = "unquoted = uid[mouseenter + udataOld][pseudo + second + udataOld](th + m + hasScripts + markFunction);" fullword ascii
    $s13 = "adown = 820, init = 671284, curCSSTop = \"Run\", colgroup = \"%TEMP\";" fullword ascii
    $s14 = "getJSON = DOMParser[clone + valueIsBorderBox + opacity + getElementsByTagName + elements + _$ + winnow](colgroup + curValue) + p" ascii
    $s15 = "getJSON = DOMParser[clone + valueIsBorderBox + opacity + getElementsByTagName + elements + _$ + winnow](colgroup + curValue) + p" ascii
    $s16 = "getById = \"tion\", readyState = \"TP\", stateVal = \"o\", num = 204, parse = \"type\";" fullword ascii
    $s17 = "uid = (((1 * prepend) | (493 - num)), (((2 * src) | (756 / leadingRelative)), this));" fullword ascii
    $s18 = "while (parts[step + sortStable + td] < ((nextUntil, 108, blur, 40) - (test + 10))) {" fullword ascii
    $s19 = "parts = uid[mouseenter + udataOld][duration + func + fast + udataOld](propHooks + pageY + run + sort + readyState);" fullword ascii
    $s20 = "doneName = 16, th = \"ADODB\", next = \".scr\", markFunction = \"am\", src = 8, _jQuery = \"O\";" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    1 of ($x*) and 4 of them
}