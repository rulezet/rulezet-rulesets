rule sig_20160301_13f9dd5bc5116e2db429b788eef5c2fc {
  meta:
    description = "datamaliciousorder - file 20160301_13f9dd5bc5116e2db429b788eef5c2fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed6ca85773d17fd1a7bb178217a8c40b0f7aeb04ef381634912730a1ee09e858"

  strings:
    $s1 = "legalEpilogue = bananaStimulus[(\"tradition\", \"class\", \"official\", \"committee\", \"ExpandEnvironmentStrings\")]((\"obligat" ascii
    $s2 = "emic\", \"expert\", \"%TEMP%/\")) + (\"herb\", \"principle\", \"pseudonymLethal\") + (\"translator\", \"state\", \"sandwich\", " ascii
    $s3 = "technologyAuthority = (((3 * 2) ^ (102 & 66)), this);" fullword ascii
    $s4 = "while (authorityReserve[(\"basis\", \"gallery\", \"instance\", \"immune\", \"readystate\")] < ((0 / 20) | (16 / 4))) {" fullword ascii
    $s5 = "authorityReserve[(\"selective\", function String.prototype.bottleSymmetry() {" fullword ascii
    $s6 = "} catch (individualCommerce) {};" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    all of them
}