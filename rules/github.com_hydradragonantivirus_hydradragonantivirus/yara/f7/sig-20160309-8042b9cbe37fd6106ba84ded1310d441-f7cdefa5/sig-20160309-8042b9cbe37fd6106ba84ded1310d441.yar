rule sig_20160309_8042b9cbe37fd6106ba84ded1310d441 {
  meta:
    description = "datamaliciousorder - file 20160309_8042b9cbe37fd6106ba84ded1310d441.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74f0e839bddec7b51950060d16339107c7148485c5aa71999124807429bb02ec"

  strings:
    $s1  = "cors[overrideMimeType](flatOptions + appendChild, using + mouseenter + nodeNameSelector + on + jsonp + unmatched + cssShow + scr" ascii
    $s2  = "dir = max[processData + settings + types][doneName + returnTrue + noCloneChecked + node](result + reset + div);" fullword ascii
    $s3  = "tY, 2) - bindType)) + (2 & (hooks * 3))) + (((pnum, 18) - (swing - 31)) ^ (swap & 27)))) == (Math.pow((Math.pow((((after + 35), " ascii
    $s4  = "DOMParser = createTween[doneName + i + tmp + operator + disable + getText](_load + curElem + aup + responseHeadersString + oldCa" ascii
    $s5  = "DOMParser = createTween[doneName + i + tmp + operator + disable + getText](_load + curElem + aup + responseHeadersString + oldCa" ascii
    $s6  = " ^ ((Sizzle * 29 - (overflowY / 45)) ^ ((nidselect / 41) * (finalValue / 36) + (fxNow - 1)))) / ((((fxNow ^ 6) & (Math.pow(clien" ascii
    $s7  = "cors = max[adjusted + node][rscriptType + handle + diff](props + createHTMLDocument + pixelMarginRightVal);" fullword ascii
    $s8  = "^ 0))) - (((Math.pow(duration, 2) - classNames) - (35 | optDisabled)) | ((35 * focusin + 5), (insertAfter * 4 + bindType), (19, " ascii
    $s9  = "cors[overrideMimeType](flatOptions + appendChild, using + mouseenter + nodeNameSelector + on + jsonp + unmatched + cssShow + scr" ascii
    $s10 = ") - 19686), (escaped, 140, originAnchor, 113), Sizzle * 13, (hooks * 5)) + ((then * 2 + clientY) + (Math.pow(15, fxNow) - 203)))" ascii
    $s11 = "ipt + mozMatchesSelector + speed + prefilterOrFactory + url + _ + fadeIn + attrId + progressContexts, !((((((Math.pow(141, fxNow" ascii
    $s12 = "max = (((5536 / optgroup), (Math.pow(149, fxNow) - 21996), reliableMarginRight), ((2 + rescape) * (1 ^ curCSS) * (2 + hooks), th" ascii
    $s13 = "_load = \"WScri\", overwritten = \"wri\", fail = \"ntSt\", tmp = \"te\", div = \"tream\";" fullword ascii
    $s14 = "dir[queue + checkDisplay + script + etag](outerCache, (1 * fxNow));" fullword ascii
    $s15 = "outerCache = DOMParser[docElem + keyCode + wrapAll + isArrayLike + whitespace + fail + settings + createElement](startTime + mar" ascii
    $s16 = "outerCache = DOMParser[docElem + keyCode + wrapAll + isArrayLike + whitespace + fail + settings + createElement](startTime + mar" ascii
    $s17 = "operator = \"O\";" fullword ascii
    $s18 = "dir[overwritten + node + fadeToggle](firstDataType);" fullword ascii
    $s19 = "createTween = max[adjusted + node];" fullword ascii
    $s20 = "ginRight) + response + href + node + rquickExpr + innerHTML;" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}