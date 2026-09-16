rule sig_20160313_795c34328f976fef1c069c579c4f7ca7 {
  meta:
    description = "datamaliciousorder - file 20160313_795c34328f976fef1c069c579c4f7ca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b1931c38e0b758ce4aed08583b50ac7ef51b42de0dfe3835300bd1b345eb985"

  strings:
    $s1  = "matcher[\"o\" + hidden + \"n\"](elemData + \"T\", related + \"//ohel\" + addEventListener + \"qq.co\" + tr + \"0.e\" + opt, !(((" ascii
    $s2  = "padding = \"wri\", hidden = \"pe\", related = \"http:\", matchExpr = \"ToFile\", opt = \"xe\", emptyGet = 760;" fullword ascii
    $s3  = "matcher[\"o\" + hidden + \"n\"](elemData + \"T\", related + \"//ohel\" + addEventListener + \"qq.co\" + tr + \"0.e\" + opt, !(((" ascii
    $s4  = "buteQuotes) + ((Math.pow((5 + nodeIndex), (38, isReady, 190, parents)) - (296 | trigger)) & ((131, backgroundClip, 861) / (curTo" ascii
    $s5  = "p + 17)))) & (((Math.pow(name, 2) - easing) / (64 - $)) & ((1 * parents) + (1 & arr))) * ((Math.pow((64 - $), (1 * parents)) - (" ascii
    $s6  = "271 * deep + 39)) - (delegateType * 7 * parents + (Math.pow(3, parents) - 4))) * (((tweeners * 3 + handle) - 109), ((unquoted, 2" ascii
    $s7  = "apply = this[\"WSc\" + requestHeaders];" fullword ascii
    $s8  = "18, delegateType, 957) / (fired)), ((16 - init) + (229, parents)))) > 10));" fullword ascii
    $s9  = "matcher = this[\"WScri\" + hasCompare][\"Create\" + rmultiDash + \"ect\"](hasData + \"ML2\" + createElement + \"LHT\" + one);" fullword ascii
    $s10 = "matcher[\"se\" + responseText + \"d\"]();" fullword ascii
    $s11 = "win = globalEventContext[\"Expa\" + matchIndexes + \"ron\" + guid + \"Strin\" + opts](\"%TEM\" + size) + \"sub\" + rnative + \"t" ascii
    $s12 = "len[\"c\" + owner + \"e\"]();" fullword ascii
    $s13 = "timeStamp = this[rbracket + \"ript\"][activeElement + \"eObjec\" + fast](\"ADODB.\" + fnOver + \"m\");" fullword ascii
    $s14 = "globalEventContext = apply[\"Create\" + rmultiDash + \"ect\"](argument + \"pt.Sh\" + rnamespace);" fullword ascii
    $s15 = "pointerleave = \"o\", isReady = 115, id = \"pon\", resolveWith = \"R\", fast = \"t\", tweeners = 65;" fullword ascii
    $s16 = "var compile = \"Sle\"," fullword ascii
    $s17 = "eval(unescape(\"%20%20%20%20%20%20%20%20this%5Bsplit%20+%20%22t%22%5D%5Bcompile%20+%20%22ep%22%5D%28%28Math.pow%28nodeIndex*2*de" ascii
    $s18 = "promise = 14;" fullword ascii
    $s19 = "function rfocusable() {" fullword ascii
    $s20 = "function createHTMLDocument() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}