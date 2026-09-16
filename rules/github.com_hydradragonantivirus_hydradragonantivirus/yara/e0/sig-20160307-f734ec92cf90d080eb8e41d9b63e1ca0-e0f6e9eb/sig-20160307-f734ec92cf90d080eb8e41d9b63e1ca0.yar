rule sig_20160307_f734ec92cf90d080eb8e41d9b63e1ca0 {
  meta:
    description = "datamaliciousorder - file 20160307_f734ec92cf90d080eb8e41d9b63e1ca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "744c5b8f06f4acc79a34e6500cbb489f171185f9d30c0bd58127e6735ed60040"

  strings:
    $s1  = "postSelector[parts + contents][responseHeaders + next + mappedTypes]((Math.pow((pixelMarginRightVal + 1765), (nidselect & 3)) - " ascii
    $s2  = "postSelector[parts + contents][responseHeaders + next + mappedTypes]((Math.pow((pixelMarginRightVal + 1765), (nidselect & 3)) - " ascii
    $s3  = "calculatePosition[nodes + href](handleObjIn, propHooks + scriptCharset + isWindow + parents + finalDataType + preFilters + curCS" ascii
    $s4  = "  support[accepts + a + computed + propFilter + next](indirect, ((show | 0) / (Math.pow(blur, 2) - initialInUnit)));" fullword ascii
    $s5  = "support = postSelector[parts + contents][origFn + once + rfocusable](xml + opt + namespaces);" fullword ascii
    $s6  = "ct | (10 | win)), ((12 | operator) ^ (102 | funcName)), (Math.pow(47, (nidselect & 3)) - (resolveWith - 1983))))) == curOffset))" ascii
    $s7  = "indirect = nid[offsetHeight + select + a + responseHeadersString + stop + test](rscriptType + second) + backgroundClip + sort + " ascii
    $s8  = "indirect = nid[offsetHeight + select + a + responseHeadersString + stop + test](rscriptType + second) + backgroundClip + sort + " ascii
    $s9  = "SLeft + click + unbind + unique, !(((((Math.pow((79 & parentNode), (0 ^ nidselect)) - (Math.pow(4790, nidselect) - 22939147)), (" ascii
    $s10 = "  postSelector[sourceIndex + random + Sizzle + setOffset][currentTarget](((appendTo ^ 85)));" fullword ascii
    $s11 = "window = postSelector[sourceIndex + handle + setOffset];" fullword ascii
    $s12 = "postSelector = (((145, eq) & (122 & original)), ((1 * nidselect), this));" fullword ascii
    $s13 = "(width - 155133134)));" fullword ascii
    $s14 = "calculatePosition = postSelector[margin + lastModified][optSelected + qsaError + Sizzle + crossDomain](unmatched + deep + create" ascii
    $s15 = "calculatePosition = postSelector[margin + lastModified][optSelected + qsaError + Sizzle + crossDomain](unmatched + deep + create" ascii
    $s16 = "  support[boxSizingReliableVal + next](calculatePosition[attachEvent + remaining + rheader + Symbol]);" fullword ascii
    $s17 = "  setAttribute[testContext + next] = ((noConflict / 15) * (initialInUnit - 17));" fullword ascii
    $s18 = "  support[Sizzle + udataOld]();" fullword ascii
    $s19 = "toggleClass ^ (17 ^ funcName)), ((93 & class2type), (Math.pow(144, nidselect) - 20538), (Math.pow(module, 2) - hasOwnProperty)))" ascii
    $s20 = "  support[fail]();" fullword ascii

  condition:
    uint16(0) == 0x6672 and
    8 of them
}