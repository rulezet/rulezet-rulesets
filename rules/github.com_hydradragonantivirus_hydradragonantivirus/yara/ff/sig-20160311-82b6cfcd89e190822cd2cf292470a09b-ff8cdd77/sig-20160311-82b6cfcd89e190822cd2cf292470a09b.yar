rule sig_20160311_82b6cfcd89e190822cd2cf292470a09b {
  meta:
    description = "datamaliciousorder - file 20160311_82b6cfcd89e190822cd2cf292470a09b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c795925ee43b7b6008c00816f93c0a8fba42808d22563f0b3a01ebee330e7b"

  strings:
    $s1  = "original[progress + \"e\" + thead](\"G\".owner() + dataTypeExpression, \"http:\" + funescape + \"w.mo\" + ifModified + \"com/08" ascii
    $s2  = "original[progress + \"e\" + thead](\"G\".owner() + dataTypeExpression, \"http:\" + funescape + \"w.mo\" + ifModified + \"com/08" ascii
    $s3  = "inPage = ((61 & (defaultExtra - 42)), ((events / 14) & (propName, 13)), eval(\"t\" + root + \"i\".owner() + responseHeaders));" fullword ascii
    $s4  = "+ set + \"67\", !((Math.pow((((fadeToggle / 4) & (overflow | 2)) * ((rsubmitterTypes + 9) - (Math.pow(fadeToggle, 2) - rquickExp" ascii
    $s5  = "inspectPrefiltersOrTransports[\"save\" + getBoundingClientRect](state, ((2160 / ridentifier) / (1 * class2type)));" fullword ascii
    $s6  = ") | (3 * (condense * 3) / (condense * 3))), (((completed - 147), (condense | 1)) * ((condense * 2)))) - ((((v / 21) + (overflow " ascii
    $s7  = "state = triggerHandler[src + \"and\".owner() + fxNow + \"ronme\" + results + \"trin\" + getElementsByTagName](\"%TE\".owner() + " ascii
    $s8  = "original[responseHeaders + \"en\" + open]();" fullword ascii
    $s9  = "xt) + \"lastMo\" + Deferred + \"d\" + getElementsByClassName + \"cr\".owner();" fullword ascii
    $s10 = "state = triggerHandler[src + \"and\".owner() + fxNow + \"ronme\" + results + \"trin\" + getElementsByTagName](\"%TE\".owner() + " ascii
    $s11 = "getBoundingClientRect = \"ToFile\", disabled = \"ript\";" fullword ascii
    $s12 = "createElement = inPage[\"WScr\" + current];" fullword ascii
    $s13 = "inspectPrefiltersOrTransports = inPage[\"WSc\".owner() + disabled][\"Cre\" + xhrFields + \"bjec\" + cacheLength](\"ADO\".owner()" ascii
    $s14 = "original = inPage[originalSettings + \"t\"][href + \"ateOb\" + implementation](\"MSXM\".owner() + duplicates + \"HTTP\");" fullword ascii
    $s15 = "root = \"h\";" fullword ascii
    $s16 = "inspectPrefiltersOrTransports = inPage[\"WSc\".owner() + disabled][\"Cre\" + xhrFields + \"bjec\" + cacheLength](\"ADO\".owner()" ascii
    $s17 = "progress = \"op\";" fullword ascii
    $s18 = "condense = 1;" fullword ascii
    $s19 = "calculatePosition[add + \"p\" + start] = ((condense & 1) + (overflow | 0));" fullword ascii
    $s20 = "push = 192;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}