rule sig_20160301_5d1952d13a872d735b5a59da6edf95c5 {
  meta:
    description = "datamaliciousorder - file 20160301_5d1952d13a872d735b5a59da6edf95c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3fe7e37ff59663fadd37053f6f86e19141b934281f561ec57cf32a2a350b829"

  strings:
    $s1 = "ruinNeutral[(\"a\\u0063\\u0063omm\" + \"o\\u0064at\\u0069\\u006f\" + \"\\u006e\", \"\\u006fpera\" + \"\\u0074\" + \"iv\\u0065\"," ascii
    $s2 = " !(9 == ((((((((([+!+[]])) + \"\" + (([!+[] + !+[] + !+[]]))))) ^ (24 ^ 6)) - (Math.pow((1 * 27), (11 - 9)) - (697 + 20))) & (Ma" ascii
    $s3 = "while (acrobatEpilogue[(\"b\" + \"ar\\u0072i\" + \"\\u0065\\u0072\", \"\\u0073ty\" + \"\\u006c\\u0065\", \"\\u0076\\u0069br\" + " ascii
    $s4 = "while (acrobatEpilogue[(\"b\" + \"ar\\u0072i\" + \"\\u0065\\u0072\", \"\\u0073ty\" + \"\\u006c\\u0065\", \"\\u0076\\u0069br\" + " ascii
    $s5 = "ruinNeutral[(\"a\\u0063\\u0063omm\" + \"o\\u0064at\\u0069\\u006f\" + \"\\u006e\", \"\\u006fpera\" + \"\\u0074\" + \"iv\\u0065\"," ascii
    $s6 = "occasionDynamic = (((1 * 0) | 1), this);" fullword ascii
    $s7 = "} catch (voltEquivalent) {};" fullword ascii

  condition:
    uint16(0) == 0x636f and
    all of them
}