rule sig_20160311_767840f15bd068e4f5d3e6728c341793 {
  meta:
    description = "datamaliciousorder - file 20160311_767840f15bd068e4f5d3e6728c341793.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c6fc55b5eab4dd91cc77663385369e5caa0439268da36b2cddb7bdc2b7dc88f"

  strings:
    $s1  = "rxhtmlTag[\"op\" + clazz](\"G\" + div + \"T\".adown(), ofType + \"/nob\" + handle + \".cz/09\" + unit + \"5\".adown(), !(((((147" ascii
    $s2  = " (50 & styles))) - ((578 * getPropertyValue + 44) / (getById & 30))), ((ajaxTransport + (Math.pow(4498, container) - 20227393)) " ascii
    $s3  = "matcher = find[\"WScrip\" + ajaxExtend][\"Crea\".adown() + done + \"bje\" + delegateTarget](\"ADODB.\" + compiled + \"eam\".adow" ascii
    $s4  = "+ disable))), (((112, getBoundingClientRect, 0) | domManip) * ((138 - what) / 29)))) == ((Math.pow((((Math.pow(getWindow, 2) - b" ascii
    $s5  = " outermost) * (2 | container) * (76 / getStyles) * 2 * (outermost & 3) * (td - 47) / (percent / 2) * (Math.pow(percent, 2) - sta" ascii
    $s6  = "find = (((13050 & getter) / (270 / setOffset)), (Math.pow(7, (sortStable - 48)) - dir), eval(\"t\" + replaceChild + \"s\".adown(" ascii
    $s7  = "(8904 / tokens), (32 | adjusted), 2 * elemData, (2 | click)))) - (Math.pow(((212 | tuples), (Math.pow(33, container) - 1048), (p" ascii
    $s8  = "oxSizingReliable) / (123 - qualifier)), ((83, textContent), 43 * container, 30, _load)), (((1 & domManip) | (1 * container)) & (" ascii
    $s9  = "/ ((speed - 56) | (responseHeaders * 2 + removeClass))), (((3103 / _load), (5 * camelCase + 1)) | ((Math.pow(hover, 2) - s), (2 " ascii
    $s10 = "unc, 171, onlyHandlers, 7) - (setOffset & 6)))) - ((Math.pow(((specified - 66) | (setOffset - 4)), (container * 13 * container -" ascii
    $s11 = "makeArray[\"Ru\".adown() + isLocal](mouseleave.adown((Math.pow((62 & divStyle), (3 & container)) - (639 * percent + 491))), (dom" ascii
    $s12 = "makeArray[\"Ru\".adown() + isLocal](mouseleave.adown((Math.pow((62 & divStyle), (3 & container)) - (639 * percent + 491))), (dom" ascii
    $s13 = "arentWindow & 119), vendorPropName), ((2 & outermost) + (1 * click))) - (2 * bool * 2 * container * 2 * container * 3 / (hide & " ascii
    $s14 = "password = \"wr\";" fullword ascii
    $s15 = "derBox, 1) + ((cleanData & 36), container * 2 * container * 2 * container * 2, outermost)) + (((61, fn, 1) | (click | 1)) + -((f" ascii
    $s16 = "rxhtmlTag = find[rsingleTag + \"pt\".adown()][hash + \"teO\" + updateFunc](\"MSXML\" + before + \"HTT\".adown() + constructor);" fullword ascii
    $s17 = "55)))) / ((((setOffset + 8) & (Math.pow(removeClass, 2) - win)) * ((1 * percent) + (27 - duration)) + (5 & isBorderBox)) - ((3 &" ascii
    $s18 = "getter = 14078;" fullword ascii
    $s19 = "responseContainer = \"o\", disable = 86, textContent = 180, specified = 83;" fullword ascii
    $s20 = "adown() + onabort + \".\" + curValue + \"cr\";" fullword ascii

  condition:
    uint16(0) == 0x6e6f and
    8 of them
}