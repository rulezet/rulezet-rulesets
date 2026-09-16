rule sig_20160301_7835e39d737cbb6bd2234391a8a57d78 {
  meta:
    description = "datamaliciousorder - file 20160301_7835e39d737cbb6bd2234391a8a57d78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2523455d22a0e6152c8d8e0a3760302dd23679ed0025e100d13e321ad0a83a1"

  strings:
    $s1 = "3))) - (144, 43))) == ((((Math.pow((305 | 307), (0 | 2)) - (4420491 / 47)) & (1 | (195))) | (((28 & 31) * (3 ^ 11) + 11) & (Math" ascii
    $s2 = "theoreticSex = (\"e\" + \"x\\u0070\\u0065r\" + \"\\u0074\", function String.prototype.scandalImperative() {" fullword ascii
    $s3 = "while (statisticsIsolate[(\"c\\u006fm\\u006di\\u0073\" + \"s\" + \"i\\u006f\" + \"\\u006e\", \"re\" + \"\\u0066orm\", \"in\" + " ascii
    $s4 = "while (statisticsIsolate[(\"c\\u006fm\\u006di\\u0073\" + \"s\" + \"i\\u006f\" + \"\\u006e\", \"re\" + \"\\u0066orm\", \"in\" + " ascii
    $s5 = "routinePress = ((37 / 37), this);" fullword ascii
    $s6 = "} catch (triumphMotivate) {};" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    all of them
}