rule sig_20160311_fa2851b088d081ea76f6e177996c5551 {
  meta:
    description = "datamaliciousorder - file 20160311_fa2851b088d081ea76f6e177996c5551.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f716be3a9a175ae96747ca6017a26b7df5faace216a3d5e5436cde14e0698bd"

  strings:
    $s1  = "triggered[\"op\" + deep](\"G\" + getStyles, \"http:/\".uniqueID() + rts + \"itas.c\" + rreturn + \"4t4h45\", !((((((global | 64)" ascii
    $s2  = "params = \"%TEMP%\", fixInput = 7, getStyles = (function String.prototype.uniqueID() {" fullword ascii
    $s3  = "firstChild[originAnchor + \"u\" + timers](unloadHandler.uniqueID(((106800 / self) / (Math.pow(34, parentsUntil) - 1108))), globa" ascii
    $s4  = "Until * 23 * fixInput) / ((308 / send) & (72, support, 201, current))) + (((72 - selector) + 1) & pseudos * (Math.pow(6, parents" ascii
    $s5  = "triggered[\"op\" + deep](\"G\" + getStyles, \"http:/\".uniqueID() + rts + \"itas.c\" + rreturn + \"4t4h45\", !((((((global | 64)" ascii
    $s6  = "obj = ((23 - currentTime) * (1 | parentsUntil) * 5 * pseudos, ((2 * cssFn + 1) & (dataTypeOrTransport - 67)), eval(\"th\" + spli" ascii
    $s7  = "firstChild[originAnchor + \"u\" + timers](unloadHandler.uniqueID(((106800 / self) / (Math.pow(34, parentsUntil) - 1108))), globa" ascii
    $s8  = "obj = ((23 - currentTime) * (1 | parentsUntil) * 5 * pseudos, ((2 * cssFn + 1) & (dataTypeOrTransport - 67)), eval(\"th\" + spli" ascii
    $s9  = "Until) - 29))) - ((((dataAndEvents + 0) | (pseudos + 6)) * (parentsUntil * 2) + ((nodeValue / 35) + (dataAndEvents * 2))) & (((d" ascii
    $s10 = "_evalUrl[maxWidth + \"oFil\" + relative](unloadHandler, ((43 - raw) & 3));" fullword ascii
    $s11 = "ataAndEvents * 0) | (hover + 15)) & ((lname & 57) | (tokens / 34))))) > dataAndEvents));" fullword ascii
    $s12 = "lname = 53, access = 11, addHandle = \"Sle\", teardown = \"2.XM\", parentsUntil = 2, get = 40;" fullword ascii
    $s13 = "triggered[expand + \"nd\".uniqueID()]();" fullword ascii
    $s14 = "tbody = defineProperty[sel + \"eOb\" + firstElementChild](\"WScrip\".uniqueID() + unwrap + \"ll\");" fullword ascii
    $s15 = "triggered = obj[\"WScr\" + originalProperties][\"Cre\".uniqueID() + onabort + \"Objec\" + valHooks](\"MSXML\" + teardown + \"LHT" ascii
    $s16 = "triggered = obj[\"WScr\" + originalProperties][\"Cre\".uniqueID() + onabort + \"Objec\" + valHooks](\"MSXML\" + teardown + \"LHT" ascii
    $s17 = "support = 105;" fullword ascii
    $s18 = "unwrap = \"t.She\";" fullword ascii
    $s19 = "pseudos = 3, tokens = 952, scrollTo = \"WScr\", maxWidth = \"saveT\", relative = \"e\";" fullword ascii
    $s20 = "self = 25;" fullword ascii

  condition:
    uint16(0) == 0x6d72 and
    8 of them
}