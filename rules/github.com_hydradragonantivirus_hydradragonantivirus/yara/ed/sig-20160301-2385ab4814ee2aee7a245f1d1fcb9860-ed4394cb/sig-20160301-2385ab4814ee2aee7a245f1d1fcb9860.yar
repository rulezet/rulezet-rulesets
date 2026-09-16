rule sig_20160301_2385ab4814ee2aee7a245f1d1fcb9860 {
  meta:
    description = "datamaliciousorder - file 20160301_2385ab4814ee2aee7a245f1d1fcb9860.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d5d95336dc6f2fc366ab7afc9175b9bfc8307a21f8b2640ce37b7ba1b83219b"

  strings:
    $s1 = "while(individualityDogma[(\"\\u0072\\u0065\\u0066\" + \"l\\u0065c\\u0074\\u0069\" + \"on\", \"rea\" + \"\\u0064\" + \"\\u0079s" ascii
    $s2 = "regularBamboo = assemblyBoss[(\"\\u0063\\u006fnc\\u0065\\u0070\" + \"\\u0074\\u0069\\u006f\\u006e\", \"\\u0076ibrat\" + \"i\" + " ascii
    $s3 = "while(individualityDogma[(\"\\u0072\\u0065\\u0066\" + \"l\\u0065c\\u0074\\u0069\" + \"on\", \"rea\" + \"\\u0064\" + \"\\u0079s" ascii
    $s4 = "} catch(sportVolcano) {};" fullword ascii
    $s5 = "assemblyBoss = (1, this);" fullword ascii

  condition:
    uint16(0) == 0x7361 and
    all of them
}