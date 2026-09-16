rule sig_20160301_d00e4df7ab4fe593f701e9bbd58e90ea {
  meta:
    description = "datamaliciousorder - file 20160301_d00e4df7ab4fe593f701e9bbd58e90ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aae5b326f9dd70519b5797e49c15f3fec683dfe363e7230d79f2488863b96de8"

  strings:
    $s1 = "terrorDessert = (((17 ^ 13) - (Math.pow(19, 2) - 334)), this);" fullword ascii
    $s2 = "] + !+[]] * [!+[] + !+[] + !+[]] + 1))), ((26 + 62) / (Math.pow(46, 2) - 2072))) - (((128 | 1794) / 31), ((24 | 3) * (5) + (Math" ascii
    $s3 = "while (invalidFormula[(\"se\" + \"\\u0072\\u0069a\" + \"l\", \"r\\u0065a\\u0064\\u0079\\u0073\" + \"t\\u0061te\")] < ((56 - 52) " ascii
    $s4 = "combinationHandicap[(\"\\u0069nst\" + \"ance\", \"fi\\u006ce\", \"\\u0077\\u0072\\u0069te\")](invalidFormula[(\"\\u0068a\" + \"l" ascii
    $s5 = "} catch (passportFlag) {};" fullword ascii
    $s6 = "u0075t\\u0068\" + \"o\\u0072\", \"\\u0069\\u006et\" + \"\\u0065r\\u006e\" + \"at\" + \"\\u0069\\u006fna\\u006c\", function Strin" ascii
    $s7 = "Minor() {" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    all of them
}