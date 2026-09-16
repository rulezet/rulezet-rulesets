rule sig_20160301_93830489ded50bb03f60875765b38bad {
  meta:
    description = "datamaliciousorder - file 20160301_93830489ded50bb03f60875765b38bad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29eff29831753c573e022031724f960bcee8c81ec296a8148421553ec24f46af"

  strings:
    $s1 = "presumptionMuseum = (((Math.pow(7077, 2) - 50075354) / (77 - 28)), this);" fullword ascii
    $s2 = "while (momentDepartment[(\"\\u0072\\u0065ady\\u0073ta\\u0074e\")] < ((0 ^ 4) / (87, 222, 238, 1))) {" fullword ascii
    $s3 = "museumCaste = televisionNorm[(\"pre\\u0066ix\", function String.prototype.motorPedal() {" fullword ascii
    $s4 = "} catch (iconThermometer) {};" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}