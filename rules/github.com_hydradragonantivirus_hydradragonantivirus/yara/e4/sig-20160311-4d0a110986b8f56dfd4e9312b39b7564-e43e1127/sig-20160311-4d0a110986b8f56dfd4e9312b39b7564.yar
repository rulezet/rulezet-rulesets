rule sig_20160311_4d0a110986b8f56dfd4e9312b39b7564 {
  meta:
    description = "datamaliciousorder - file 20160311_4d0a110986b8f56dfd4e9312b39b7564.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "531497de64162a6ef36442be321fdf72d2804c049e4b48dc240683d5d665caed"

  strings:
    $s1  = "scrollLeft[contents + \"p\" + parts + \"n\"](elemLang + \"E\".overwritten() + css, \"http\" + crossDomain + \"aih\" + _$ + \".bi" ascii
    $s2  = "ten() + add + \"tyle\" + newDefer + \"om/\" + b + \"4\".overwritten(), !((((1 * (rheaders & 3)) * (Math.pow((style | 2), rheader" ascii
    $s3  = "s)))) * ((((Math.pow(25, rheaders) - 578) * (rheaders & 3) + (setMatcher / 39)) + (groups / 36)) / ((Math.pow((before - 51), (at" ascii
    $s4  = "scrollLeft[contents + \"p\" + parts + \"n\"](elemLang + \"E\".overwritten() + css, \"http\" + crossDomain + \"aih\" + _$ + \".bi" ascii
    $s5  = "scrollLeft = step[eq + \"ipt\".overwritten()][getComputedStyle + \"ateOb\" + elemData](\"MSXML\" + factory + \"LHTTP\".overwritt" ascii
    $s6  = "48 | clearQueue)) - (((102 - cssPrefixes), (140 | groups), (3 * offsetWidth + 2)) & ((rheaders | 4) + (rheaders * 20 + attribute" ascii
    $s7  = "ndTo) - (Math.pow(48, rheaders) - 2237)) - ((fadeOut | 84) / (Math.pow(getAttributeNode, 2) - always)))) * ((((39, Data, 232, ca" ascii
    $s8  = "winnow = step[hasCompare + \"pt\"][image + \"teObj\".overwritten() + splice](\"ADODB.\" + iframe + \"eam\");" fullword ascii
    $s9  = "step = ((Math.pow((191 + pointerleave), (1 + attributes)) - (173, ready, 43, appendChild)), ((9 * callbackExpect) / (2 * appendT" ascii
    $s10 = "step = ((Math.pow((191 + pointerleave), (1 + attributes)) - (173, ready, 43, appendChild)), ((9 * callbackExpect) / (2 * appendT" ascii
    $s11 = "tributes * 2)) - (postSelector, 225, second)) | ((4 & camelCase) + (66 - type))))) == (((1 + requestHeadersNames) * (((89 - appe" ascii
    $s12 = "winnow[isPlainObject + \"ToF\" + progressContexts](inspect, ((1 | _load) - (30 + attributes)));" fullword ascii
    $s13 = "inspect = values[\"Expan\" + optgroup + \"iro\" + addEventListener + \"tSt\".overwritten() + nodeValue + \"gs\"](rts + \"%/\") +" ascii
    $s14 = "inspect = values[\"Expan\" + optgroup + \"iro\" + addEventListener + \"tSt\".overwritten() + nodeValue + \"gs\"](rts + \"%/\") +" ascii
    $s15 = "rts = \"%TEMP\", elemData = \"ject\", structure = \"nts\", attributes = 1, initialInUnit = \"sc\";" fullword ascii
    $s16 = "contents = \"o\";" fullword ascii
    $s17 = "styles = 9, requestHeadersNames = 0, constructor = \"pt\", protocol = \"op\";" fullword ascii
    $s18 = "rquery = step[\"WScri\".overwritten() + constructor];" fullword ascii
    $s19 = "e + \"AndEve\".overwritten() + structure + \".\" + initialInUnit + \"r\";" fullword ascii
    $s20 = "values = rquery[\"Cre\" + timer + \"ject\"](clientY + \"t.Sh\".overwritten() + idx);" fullword ascii

  condition:
    uint16(0) == 0x7165 and
    8 of them
}