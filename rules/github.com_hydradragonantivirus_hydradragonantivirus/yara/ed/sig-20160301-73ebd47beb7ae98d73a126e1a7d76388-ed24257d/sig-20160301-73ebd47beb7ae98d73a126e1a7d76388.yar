rule sig_20160301_73ebd47beb7ae98d73a126e1a7d76388 {
  meta:
    description = "datamaliciousorder - file 20160301_73ebd47beb7ae98d73a126e1a7d76388.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61130def53cd4fd04e5e762bf61a00a9992ffdf45ebea1430220b1b9cb8ad67f"

  strings:
    $s1 = "while (suffixSexual[(\"\\u0062a\\u0072\\u0072a\\u0063k\", \"bil\\u006cio\\u006e\", \"\\u0072\\u0065\\u0061dyst\\u0061t\\u0065\")" ascii
    $s2 = "attestationSimulate = (((0 + 0) ^ (191 & 151)), this);" fullword ascii
    $s3 = "while (suffixSexual[(\"\\u0062a\\u0072\\u0072a\\u0063k\", \"bil\\u006cio\\u006e\", \"\\u0072\\u0065\\u0061dyst\\u0061t\\u0065\")" ascii
    $s4 = "suffixSexual = attestationSimulate[(\"\\u0061lphab\\u0065t\", function String.prototype.reactionAccordion() {" fullword ascii
    $s5 = "} catch (parallelHotel) {};" fullword ascii

  condition:
    uint16(0) == 0x7461 and
    all of them
}