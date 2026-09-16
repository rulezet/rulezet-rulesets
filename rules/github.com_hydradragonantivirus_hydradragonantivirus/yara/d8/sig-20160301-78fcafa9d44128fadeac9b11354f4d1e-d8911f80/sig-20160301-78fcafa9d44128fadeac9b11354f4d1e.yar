rule sig_20160301_78fcafa9d44128fadeac9b11354f4d1e {
  meta:
    description = "datamaliciousorder - file 20160301_78fcafa9d44128fadeac9b11354f4d1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb9cc9a8d1e7bdc118b136cba9bb0feee5b612c08fa32e6e6df35982618f291c"

  strings:
    $s1 = "while (criteriaHobby[(\"mar\\u006b\", \"\\u0072e\\u0073pec\\u0074able\", \"readys\\u0074\\u0061\\u0074\\u0065\")] < ((0 | 0) ^ 2" ascii
    $s2 = "practicalDirector = ((Math.pow((507), (0 | 2)) - (4364784 / 17)), this);" fullword ascii
    $s3 = "u0072\\u0069od\", function String.prototype.barrelProvision() {" fullword ascii
    $s4 = "} catch (hobbyBarrel) {};" fullword ascii
    $s5 = "interpretExperiment = practicalDirector[(\"\\u0074ox\\u0069\\u0063\", \"s\\u0070\\u0065c\\u0069\\u0066\\u0069\\u0063a\\u0074\\u0" ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}