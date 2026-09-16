rule sig_20160308_991e85a1485e69f3f51a479a7b12099e {
  meta:
    description = "datamaliciousorder - file 20160308_991e85a1485e69f3f51a479a7b12099e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d6714b6e3278fddf82ef5dc31bbc1516c9f1dbd92966415d623faa655aa67de"

  strings:
    $s1  = "contexts[isWindow](width, each + getResponseHeader + rrun + matchIndexes + readyList + getElementsByName + rfocusable + resolve " ascii
    $s2  = "show[unbind + firstDataType][propFix + Deferred](((45542 / get) * (Math.pow(3, replaceWith) - 5) + (colgroup - 2017)));" fullword ascii
    $s3  = "filter = prefilterOrFactory[nextUntil + open + args + rscriptType + namespace](radioValue + cos + throws) + token + getClientRec" ascii
    $s4  = "filter = prefilterOrFactory[nextUntil + open + args + rscriptType + namespace](radioValue + cos + throws) + token + getClientRec" ascii
    $s5  = "show = (((11 * getAll + 1) | (define - 246)), (((qsaError | 2) + (e * 2)), this));" fullword ascii
    $s6  = "nObject) / (50 & rxhtmlTag)))) ^ (((1 ^ (computeStyleTests, 101, size, 0)) * ((opt - 101) - (special / 27))) - (Math.pow(((isHid" ascii
    $s7  = "contexts[isWindow](width, each + getResponseHeader + rrun + matchIndexes + readyList + getElementsByName + rfocusable + resolve " ascii
    $s8  = "onerror[parents + oldfire + state + fnOver] = (qsaError + -1);" fullword ascii
    $s9  = "fixHooks = show[createTween + start + firstDataType][responseContainer + firing + newSelector + getResponseHeader](resolveWith +" ascii
    $s10 = "boolHook = show[stored + getResponseHeader];" fullword ascii
    $s11 = "fixHooks[left + fadeTo](contexts[time + getAttribute + addHandle]);" fullword ascii
    $s12 = "funescape[input + fn] = ((optDisabled - 33), (fixInput, 112, get, 1));" fullword ascii
    $s13 = "fixHooks = show[createTween + start + firstDataType][responseContainer + firing + newSelector + getResponseHeader](resolveWith +" ascii
    $s14 = "show[matchContext + trim][rhash + parents](((19 ^ suffix) + (1586 / col)));" fullword ascii
    $s15 = "readyList = \"rf\", newSelector = \"Objec\", token = \"orig\";" fullword ascii
    $s16 = "contexts = show[success + parentOffset][factory + fadeTo + oldCache + serialize](cssShow + fired + getElementsByClassName + _dat" ascii
    $s17 = "contexts = show[success + parentOffset][factory + fadeTo + oldCache + serialize](cssShow + fired + getElementsByClassName + _dat" ascii
    $s18 = "while (contexts[all + emptyGet + params + fadeTo] < ((5 & escapedWhitespace) & (4 ^ e))) {" fullword ascii
    $s19 = "var width = \"GET\"," fullword ascii
    $s20 = "prefilterOrFactory = boolHook[DOMParser + dir + returned + nodeType + serialize](createTween + globalEventContext + j + firstEle" ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}