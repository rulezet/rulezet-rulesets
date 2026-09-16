rule sig_20160301_79b435c8557516d18d0280054947309d {
  meta:
    description = "datamaliciousorder - file 20160301_79b435c8557516d18d0280054947309d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea2c1782e77e33b4e4f4d3ff2d7c6f4bf610ed4bef2224c865133a845da9e509"

  strings:
    $s1 = "while(clipPreamble[(\"\\u0065pi\\u006co\\u0067\" + \"\\u0075\" + \"\\u0065\", \"\\u0072\" + \"\\u0065a\" + \"dys\\u0074\\u0061\"" ascii
    $s2 = "while(clipPreamble[(\"\\u0065pi\\u006co\\u0067\" + \"\\u0075\" + \"\\u0065\", \"\\u0072\" + \"\\u0065a\" + \"dys\\u0074\\u0061\"" ascii
    $s3 = "anecdoteVersion = (((1 | 0) | (0 ^ 1)), this);" fullword ascii
    $s4 = "} catch(principleComposer) {};" fullword ascii
    $s5 = "    amortizationPrimitive[(\"\\u0062\\u0069na\" + \"\\u0072y\", function String.prototype.penaltyAbsorption() {" fullword ascii

  condition:
    uint16(0) == 0x6e61 and
    all of them
}