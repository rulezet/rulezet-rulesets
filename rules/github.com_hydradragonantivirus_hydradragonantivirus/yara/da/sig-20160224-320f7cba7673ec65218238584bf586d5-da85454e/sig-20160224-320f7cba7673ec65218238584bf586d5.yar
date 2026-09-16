rule sig_20160224_320f7cba7673ec65218238584bf586d5 {
  meta:
    description = "datamaliciousorder - file 20160224_320f7cba7673ec65218238584bf586d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a206afd257633e2d7f1f2babcbc5e019c62cb2c6a9b2747d7a8944e3be62d40d"

  strings:
    $s1 = "\\u002F87h\\u0037\\u0035\\u0034', false);" fullword ascii
    $s2 = "var vCxCDqd= this['\\u0041\\u0063\\u0074\\u0069\\u0076e\\u0058\\u004F\\u0062\\u006A\\u0065c\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}