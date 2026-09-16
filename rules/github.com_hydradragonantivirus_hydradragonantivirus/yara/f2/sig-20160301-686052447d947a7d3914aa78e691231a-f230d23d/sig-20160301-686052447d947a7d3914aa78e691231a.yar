rule sig_20160301_686052447d947a7d3914aa78e691231a {
  meta:
    description = "datamaliciousorder - file 20160301_686052447d947a7d3914aa78e691231a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "288f3ae7be52fcd3d0c5f95080a6861b7f12384121e3769db466245dd51676b2"

  strings:
    $s1 = "delegationModern = (((293 - 164) | (322 - 177)), this);" fullword ascii
    $s2 = "while(aviationAirplane[(\"read\\u0079s\\u0074a\\u0074\\u0065\")] < (1 * (4 | 0))) {" fullword ascii
    $s3 = "boardAcademy[(\"\\u0063\\u006ca\\u0073\\u0073\", \"\\u006c\\u0069m\\u0069t\", function String.prototype.terminologyDouble() {" fullword ascii
    $s4 = "} catch(paradoxCube) {};" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    all of them
}