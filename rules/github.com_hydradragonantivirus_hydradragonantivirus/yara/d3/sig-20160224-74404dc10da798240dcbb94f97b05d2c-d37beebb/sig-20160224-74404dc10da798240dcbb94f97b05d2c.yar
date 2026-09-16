rule sig_20160224_74404dc10da798240dcbb94f97b05d2c {
  meta:
    description = "datamaliciousorder - file 20160224_74404dc10da798240dcbb94f97b05d2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec9847b9e858c4f091f2fa6c13092f7d731a842fe7cf273d2370152bcb16f648"

  strings:
    $s1 = "\\u0037\\u0068\\u0037\\u0035\\u0034', false);" fullword ascii
    $s2 = "var WXukCY= this['A\\u0063t\\u0069\\u0076\\u0065X\\u004F\\u0062\\u006A\\u0065\\u0063\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}