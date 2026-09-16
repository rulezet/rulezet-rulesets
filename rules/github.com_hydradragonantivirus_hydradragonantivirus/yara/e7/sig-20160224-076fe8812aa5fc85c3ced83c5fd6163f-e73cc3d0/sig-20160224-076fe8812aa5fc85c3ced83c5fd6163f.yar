rule sig_20160224_076fe8812aa5fc85c3ced83c5fd6163f {
  meta:
    description = "datamaliciousorder - file 20160224_076fe8812aa5fc85c3ced83c5fd6163f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52beacf30321901abe71f2b2caa25702dcf18cd7ad9c034a59b0430e096222bc"

  strings:
    $s1 = "var YyNofa= this['\\u0041\\u0063\\u0074iv\\u0065\\u0058\\u004F\\u0062\\u006A\\u0065\\u0063t'];" fullword ascii
    $s2 = "02Fs\\u0079s\\u0074e\\u006D\\u002Fca\\u0063\\u0068\\u0065/8\\u0037\\u0068\\u0037\\u0035\\u0034', false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}