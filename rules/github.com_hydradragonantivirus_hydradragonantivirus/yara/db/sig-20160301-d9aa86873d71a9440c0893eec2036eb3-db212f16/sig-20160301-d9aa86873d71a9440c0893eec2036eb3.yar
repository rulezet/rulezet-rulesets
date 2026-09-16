rule sig_20160301_d9aa86873d71a9440c0893eec2036eb3 {
  meta:
    description = "datamaliciousorder - file 20160301_d9aa86873d71a9440c0893eec2036eb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eda3b34d97155cf20cb8112e25219ae371f52c972d3110e3fe72c811746f55c4"

  strings:
    $s1 = "while(scandalScalpel[(\"\\u0072\\u0065ady\\u0073\\u0074\\u0061te\")] < ((([!+[] + !+[]]) * ([!+[] + !+[]])) ^ (0 | 0))) {" fullword ascii
    $s2 = "alternativeArctic = ((5 | 5) * (1 * 5) * (4 | 3), this);" fullword ascii
    $s3 = "clientSalon = alternativeArctic[(\"\\u0070ort\", function String.prototype.infinitiveCombine() {" fullword ascii
    $s4 = "} catch(peakPractice) {};" fullword ascii

  condition:
    uint16(0) == 0x6c61 and
    all of them
}