rule sig_20160301_a2ebf8d734e56174aa00e22bb18ebce2 {
  meta:
    description = "datamaliciousorder - file 20160301_a2ebf8d734e56174aa00e22bb18ebce2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1433b34b56367f9c820f4d6a889e212cf56388cdd4fca10cde988d204b5f30a6"

  strings:
    $s1 = "blockTribune[(\"m\\u0061\\u0073\" + \"\\u0074\" + \"e\\u0072\", function String.prototype.binaryBalloon() {" fullword ascii
    $s2 = "while (crisisEffective[(\"de\" + \"l\\u0065ga\" + \"tio\\u006e\", \"\\u0072\\u0065a\\u0064y\\u0073\" + \"\\u0074at\\u0065\")] < " ascii
    $s3 = "while (crisisEffective[(\"de\" + \"l\\u0065ga\" + \"tio\\u006e\", \"\\u0072\\u0065a\\u0064y\\u0073\" + \"\\u0074at\\u0065\")] < " ascii
    $s4 = "depositArena = ((([+!+[]])), this);" fullword ascii
    $s5 = "} catch (raidArmy) {};" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    all of them
}