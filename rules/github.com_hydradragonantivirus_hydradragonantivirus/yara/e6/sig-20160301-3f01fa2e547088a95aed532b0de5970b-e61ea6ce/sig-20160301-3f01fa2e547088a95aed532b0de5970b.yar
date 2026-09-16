rule sig_20160301_3f01fa2e547088a95aed532b0de5970b {
  meta:
    description = "datamaliciousorder - file 20160301_3f01fa2e547088a95aed532b0de5970b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2ec1f25bafcd99883ff67a2f8d9ab2586b7295b37a6614f223adaa196cfc134"

  strings:
    $s1 = "objectiveSymmetry = (((Math.pow(40, 2) - 1561) - (684 / 18)), this);" fullword ascii
    $s2 = "while(predicateParole[(\"\\u0072ead\" + \"\\u0079\\u0073\\u0074at\" + \"e\")] < ((141 ^ 78), (Math.pow(136, 2) - 18245), (252 - " ascii
    $s3 = "while(predicateParole[(\"\\u0072ead\" + \"\\u0079\\u0073\\u0074at\" + \"e\")] < ((141 ^ 78), (Math.pow(136, 2) - 18245), (252 - " ascii
    $s4 = "006f\" + \"\\u006e\", function String.prototype.humanCollision() {" fullword ascii
    $s5 = "motorMechanic[(\"\\u0074ran\\u0073\\u006c\" + \"ati\\u006f\" + \"n\", \"partn\\u0065\" + \"\\u0072\", \"s\\u0074\\u0069\\u006du" ascii
    $s6 = "} catch(almanacPrecedent) {};" fullword ascii

  condition:
    uint16(0) == 0x626f and
    all of them
}