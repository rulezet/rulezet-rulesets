rule sig_20160301_2d7ba9df45e416c8f0a92f6e169e8ae9 {
  meta:
    description = "datamaliciousorder - file 20160301_2d7ba9df45e416c8f0a92f6e169e8ae9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0349f58d4af9c15923b258faab949197b0ae4db5c0354fd17bad3f348fb6d7f"

  strings:
    $s1 = "imageNegative = (((1 + 120), (1 + 0)), this);" fullword ascii
    $s2 = "while (symmetricalStructure[(\"r\" + \"ead\\u0079\" + \"\\u0073\\u0074\\u0061t\\u0065\")] < ((2 | 2) * 2)) {" fullword ascii
    $s3 = "symmetricalStructure = imageNegative[(\"p\\u0072\\u006ff\" + \"ess\\u0069\" + \"\\u006f\" + \"\\u006e\", function String.prototy" ascii
    $s4 = "symmetricalStructure = imageNegative[(\"p\\u0072\\u006ff\" + \"ess\\u0069\" + \"\\u006f\" + \"\\u006e\", function String.prototy" ascii
    $s5 = "} catch (rationalMemorandum) {};" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    all of them
}