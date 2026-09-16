rule sig_20160308_947b0be529e77b489adbb6eff2af3236 {
  meta:
    description = "datamaliciousorder - file 20160308_947b0be529e77b489adbb6eff2af3236.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82ddd82bcf02c63c00d08b8021a0cd30a907fae845e7419ae580dcabe40382cb"

  strings:
    $s1  = " rhash[getWindow + specialEasing + postFilter][documentIsHTML + stopOnFalse](((Math.pow(86, radio) - 7296)));" fullword ascii
    $s2  = "slideUp[cacheURL](container + iframe, stored + nType + state + parts + tag + msMatchesSelector + innerText + valueParts + Data +" ascii
    $s3  = " current, !((((createPositionalPseudo / 38) * (attributes & 3)) * (((getClass - 4218) / (Math.pow(hash, 2) - old)), ((150 + pree" ascii
    $s4  = "rhash = (((Math.pow(35, radio) - 1186) & inspect * 2), (((doScroll - 8) + (fadeToggle * 0)), this));" fullword ascii
    $s5  = "blur = rhash[xhr + newSelector][camel + size + delegateTarget](JSON + eventDoc + original + DOMParser);" fullword ascii
    $s6  = "Value / 39)) ^ ((Math.pow(defineProperty, 2) - udataCur) & 5 * attributes)) / (((245, nextAll, 3) ^ (fadeToggle + -1)) + ((r20, " ascii
    $s7  = "blur[source + rcheckableType + onload](script, ((fadeToggle & 1) * radio));" fullword ascii
    $s8  = "colgroup = rhash[compare + subtract + bySet];" fullword ascii
    $s9  = "xisting), 13 * attributes * 2 * radio), ((2 * attributes + 1) + (attributes * 2 + fadeToggle)), (56 - origCount)) / (((1 + (node" ascii
    $s10 = "htmlPrefilter[extra + gotoEnd + idx + dir] = ((3 | height) - (2 * attributes + 1));" fullword ascii
    $s11 = "slideUp = rhash[xhr + newSelector][disconnectedMatch + serialize + removeData](selection + nidselect + needsContext);" fullword ascii
    $s12 = " high = \".scr\"," fullword ascii
    $s13 = "script = defaultPrefilter[ajaxPrefilter + removeProp + dir + rquery + Expr + rCRLF + fired](calculatePosition + preDispatch) + r" ascii
    $s14 = "script = defaultPrefilter[ajaxPrefilter + removeProp + dir + rquery + Expr + rCRLF + fired](calculatePosition + preDispatch) + r" ascii
    $s15 = "while (slideUp[appendTo + cloneNode + prev + resolve] < ((0 ^ fadeToggle) + (3 | radio))) {" fullword ascii
    $s16 = "numnonpx + unwrap + rbuggyQSA + msFullscreenElement + high;" fullword ascii
    $s17 = "blur[parse + resolve](slideUp[check + count + rdisplayswap]);" fullword ascii
    $s18 = "hash = 33;" fullword ascii
    $s19 = "fragment = \"close\", appendTo = \"re\", propName = \"el\", rnumnonpx = \"cr\", compare = \"W\";" fullword ascii
    $s20 = "slideUp[cacheURL](container + iframe, stored + nType + state + parts + tag + msMatchesSelector + innerText + valueParts + Data +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}