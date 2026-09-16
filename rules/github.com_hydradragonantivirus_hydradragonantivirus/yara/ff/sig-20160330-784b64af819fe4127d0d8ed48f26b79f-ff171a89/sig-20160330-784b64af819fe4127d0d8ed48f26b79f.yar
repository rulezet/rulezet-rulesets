rule sig_20160330_784b64af819fe4127d0d8ed48f26b79f {
  meta:
    description = "datamaliciousorder - file 20160330_784b64af819fe4127d0d8ed48f26b79f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8867b246e4b230661deb2828e39ce5ecd94049fa9aee1a280bd50527b8e90fd3"

  strings:
    $x1  = "eval(unescape([\"defaultPrevented&20&3D&20&28&22ply&22&29&2C&20operator&20&3D&20&28&22ronm&22&29&2C&20radio&20&3D&20&\", \"28&22" ascii
    $s2  = "isNumeric(createOptions, temp, emptyGet);" fullword ascii
    $s3  = "addBack[createOptions + \"ipt\"][temp + \"ep\"](((end + 535)));" fullword ascii
    $s4  = "assert[\"SaveT\" + open + \"e\"](wrapMap, ((Math.pow(mouseenter, 2) - padding) / (Math.pow(42, rwhitespace) - 1721)));" fullword ascii
    $s5  = "function bup(identifier, conditionFn, rkeyEvent) {" fullword ascii
    $s6  = "C&20css&20&3D&20&28&22http&3A&22&29&2C&20sub\", \"tract&20&3D&20&28&22She&22&29&3B_load&20&3D&20&283&29&3Btemp&20&3D&20&28&22Sle" ascii
    $s7  = "insertAfter(\"while&20&28fadeTo&5BoverrideMimeType&20+&20&22dySta&22&20+&20nid&5D&20&21&3D&20&28&2812+radioValue&29&2C&28Math.po" ascii
    $s8  = "insertAfter(\"while&20&28fadeTo&5BoverrideMimeType&20+&20&22dySta&22&20+&20nid&5D&20&21&3D&20&28&2812+radioValue&29&2C&28Math.po" ascii
    $s9  = "options(multipleContexts, temp, overrideMimeType, oldCallbacks);" fullword ascii
    $s10 = "for (delegateCount = (1 + -(eased / 7)); delegateCount < prev[\"le\" + hide]; delegateCount++) {" fullword ascii
    $s11 = "if (fadeTo[beforeSend + \"s\"] == ((visibility | 201) & (version | 70))) {" fullword ascii
    $s12 = "function DOMParser(rcomma, oMatchesSelector, pipe) {" fullword ascii
    $s13 = "rnamespace[createOptions + \"ipt\"][test + \"e\" + dest](((mouseHooks) / (251, after, 42)));" fullword ascii
    $s14 = "assert[isSuccess](fadeTo[\"respo\" + rtrim + \"Body\"]);" fullword ascii
    $s15 = "assert[initialInUnit + \"p\" + onlyHandlers + \"n\"]();" fullword ascii
    $s16 = "assert[\"mo\" + cleanData + \"e\"] = ((3 | _load) | (3 + createPseudo));" fullword ascii
    $s17 = "function off(pushStack, iframe) {" fullword ascii
    $s18 = "DOMParser(teardown, radioValue, version);" fullword ascii
    $s19 = "function pseudos() {" fullword ascii
    $s20 = "function isNumeric() {" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    1 of ($x*) and 4 of them
}