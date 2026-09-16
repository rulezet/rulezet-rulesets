rule sig_20160301_fdceeb160c0bda7506a1b749cf3d5188 {
  meta:
    description = "datamaliciousorder - file 20160301_fdceeb160c0bda7506a1b749cf3d5188.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6532c0ed7bb9ac5c841ced7072e68ef17720814df7552344ea79fca592331027"

  strings:
    $s1 = "factorPress = complexIndustrial[(\"deformation\", \"resource\", \"ExpandEnvironmentStrings\")]((\"tax\", \"resistor\", \"band\"," ascii
    $s2 = "factorPress = complexIndustrial[(\"deformation\", \"resource\", \"ExpandEnvironmentStrings\")]((\"tax\", \"resistor\", \"band\"," ascii
    $s3 = "routineAggregate = (((10 | 9) ^ (Math.pow(27, 2) - 700)), this);" fullword ascii
    $s4 = "while (collisionZone[(\"microphone\", \"amplitude\", \"component\", \"readystate\")] < ((2 ^ 6) & (3 * 2 + 1))) {" fullword ascii
    $s5 = "collisionZone = routineAggregate[(\"coordination\", \"WScript\")][(\"occupy\", \"cabin\", \"emblem\", \"religion\", function Str" ascii
    $s6 = "collisionZone = routineAggregate[(\"coordination\", \"WScript\")][(\"occupy\", \"cabin\", \"emblem\", \"religion\", function Str" ascii
    $s7 = "} catch (militaryState) {};" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    all of them
}