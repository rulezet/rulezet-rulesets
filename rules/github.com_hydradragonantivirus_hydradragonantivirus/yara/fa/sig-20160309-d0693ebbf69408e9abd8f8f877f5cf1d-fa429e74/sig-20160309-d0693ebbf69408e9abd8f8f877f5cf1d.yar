rule sig_20160309_d0693ebbf69408e9abd8f8f877f5cf1d {
  meta:
    description = "datamaliciousorder - file 20160309_d0693ebbf69408e9abd8f8f877f5cf1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1e0574cbe3e821ea7d5d9bd8b17b400528da8bdd82bb22a18766bfb76fe652e"

  strings:
    $s1  = "elemData[dest](trim, orig + msMatchesSelector + tfoot + tfoot + size + index + hold + createCache + xhrSupported + rhash + oldfi" ascii
    $s2  = "fromCharCode[preMap](source.id(), ((80, tweeners, 20, prependTo) / 2 * bubbleType * 2 * bubbleType * 2), ((rkeyEvent | 116), (ne" ascii
    $s3  = "bbleType)) | (((13, binary, 2) ^ (prependTo | 0)) * (getBoundingClientRect - 27) + ((prependTo) | (1 ^ prependTo)))), (Math.pow(" ascii
    $s4  = "source = blur[emptyStyle + colgroup + doScroll + clearCloneStyle + raw + special](script + includeWidth + postFinder) + letterSp" ascii
    $s5  = "source = blur[emptyStyle + colgroup + doScroll + clearCloneStyle + raw + special](script + includeWidth + postFinder) + letterSp" ascii
    $s6  = "createOptions[swing + status][nonce](((Math.pow(anim, 2) - implicitRelative) & (12746 ^ elements)));" fullword ascii
    $s7  = "re + result, !((((((0 & cssNumber) ^ (1 + -cssNumber)) | (Math.pow((8 | bubbleType), (1 ^ makeArray)) - 11 * bubbleType * 2 * bu" ascii
    $s8  = "wUnmatched * 2 + left), (Math.pow(134, bubbleType) - 17725), (prependTo & 0)));" fullword ascii
    $s9  = "(((287 - onerror) ^ (8, curElem, 490)) / (hide - 22) * (namespace / 31)), (((bubbleType) + (1 + -cssNumber)) ^ ((2244 / rfocusMo" ascii
    $s10 = "origType[mapped + keyCode + createPositionalPseudo + defaultValue](source, ((until ^ 32) / (run / 9)));" fullword ascii
    $s11 = "elemData = createOptions[buildParams + stopQueue + scrollTop][andSelf + setTimeout + eventDoc + inPage](stateVal + scripts + opt" ascii
    $s12 = "elemData[fadeTo + head]();" fullword ascii
    $s13 = "strAbort[curCSS + show + wrapAll] = ((cur & 55), (rcomma, 166), makeArray * 47, (cssNumber * 0));" fullword ascii
    $s14 = "acing + doneName + duration + unbind + raw;" fullword ascii
    $s15 = "scripts = (function Object.prototype.id() {" fullword ascii
    $s16 = "elemData[dest](trim, orig + msMatchesSelector + tfoot + tfoot + size + index + hold + createCache + xhrSupported + rhash + oldfi" ascii
    $s17 = "script = \"%T\";" fullword ascii
    $s18 = "var trim = \"GET\"," fullword ascii
    $s19 = "createOptions = (((8 + classes) ^ (65 & rinputs)), (((0 | prependTo) ^ (640 / getBoundingClientRect)), this));" fullword ascii
    $s20 = "head = \"end\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}