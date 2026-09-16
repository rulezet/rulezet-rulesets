rule sig_20160309_a2e98d046f96677d633b2941902aeffa {
  meta:
    description = "datamaliciousorder - file 20160309_a2e98d046f96677d633b2941902aeffa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0083d839f586caf85ace65a354de86b738f8552c3494e5ff766fd0addd66587"

  strings:
    $s1  = "funcName = checked[ridentifier + diff + val][fnOver + l](hasScripts + random + src + getById);" fullword ascii
    $s2  = "preMap = checked[ridentifier + appendChild][mappedTypes + rhtml + hasOwnProperty](success + getter + emptyStyle + version + supp" ascii
    $s3  = "t[delegateTarget + keys] = (1 * check);" fullword ascii
    $s4  = "preMap[wrapMap + events + setTimeout](proxy, marginLeft + readyWait + wrapAll + curElem + rinputs + interval + returned + xhrSup" ascii
    $s5  = "delegateType = show[then + script + define + ajaxExtend + head + fixHooks + cssFn + origCount](cur + matcherOut + subordinate) +" ascii
    $s6  = "delegateType = show[then + script + define + ajaxExtend + head + fixHooks + cssFn + origCount](cur + matcherOut + subordinate) +" ascii
    $s7  = "preMap = checked[ridentifier + appendChild][mappedTypes + rhtml + hasOwnProperty](success + getter + emptyStyle + version + supp" ascii
    $s8  = "script = \"andEn\", async = 39, cssText = \"pos\", cur = \"%TEM\", handlerQueue = \"oFile\", head = \"entStr\";" fullword ascii
    $s9  = "irstChild) / (49 & rattributeQuotes))) - (((0 | check) + (440 / urlAnchor)) ^ (Math.pow((1 + onload), (2 ^ domManip)) - (64 & rp" ascii
    $s10 = "/ 20), (startTime / 17)) - (scrollLeft & 823)) / ((Math.pow(nType, 2) - simple) + (4 * setDocument + 1)))) - ((multipleContexts " ascii
    $s11 = "ported + stateString + options + result, !(4 < ((Math.pow(((check ^ 4) & (nType | 5)) * (end, 127, curTop, 2), ((Math.pow((unit " ascii
    $s12 = "outermost = \".\", cssProps = \"ition\", success = \"M\", guid = \"seB\", matchContext = 4281, delegateTarget = \"typ\";" fullword ascii
    $s13 = "checked[ridentifier + timeout + div][addHandle](((106 - css), (Math.pow(121, Callbacks) - 14507), (Math.pow(input, 2) - matchCon" ascii
    $s14 = "checked[ridentifier + timeout + div][addHandle](((106 - css), (Math.pow(121, Callbacks) - 14507), (Math.pow(input, 2) - matchCon" ascii
    $s15 = "preMap[wrapMap + events + setTimeout](proxy, marginLeft + readyWait + wrapAll + curElem + rinputs + interval + returned + xhrSup" ascii
    $s16 = "adjustCSS = 57, wrapAll = \"v.com/\", returnTrue = \"ody\", cssFn = \"n\", check = 1, firstChild = 1385;" fullword ascii
    $s17 = "appendChild = \"Script\", marginLeft = \"http:/\", wrap = \"eate\", multipleContexts = 7, rprotocol = 83, etag = 40;" fullword ascii
    $s18 = "checked = (((244, pageX)), (((0 | domManip) | (65 - adjustCSS)), this));" fullword ascii
    $s19 = "register[startLength](delegateType.currentTime(), (0 ^ domManip), (1 + -check));" fullword ascii
    $s20 = "text), (16301 - defaultExtra)));" fullword ascii

  condition:
    uint16(0) == 0x656b and
    8 of them
}