rule sig_20160301_41ae0dd030097ac7ccd4dcb0ceb6a0a4 {
  meta:
    description = "datamaliciousorder - file 20160301_41ae0dd030097ac7ccd4dcb0ceb6a0a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d904bcac3eb8b9140a94f73a4505b4ab7e18283b1d4565fea63c2f65ae969d5"

  strings:
    $x1 = "y\", \"statistics\", \"%TEMP%/\")) + (\"progress\", \"transit\", \"result\", \"banana\", \"prologueNumeral\") + (\".scr\");" fullword ascii
    $s2 = "cameraIllustration = degradationBazaar[(\"ballast\", \"phenomenon\", \"principle\", \"service\", \"ExpandEnvironmentStrings\")](" ascii
    $s3 = "defectCamera[(\"WScript\")][(\"computer\", \"momentum\", \"population\", \"taboo\", function String.prototype.civilizationInject" ascii
    $s4 = "while (classTablet[(\"budget\", \"manuscript\", \"readystate\")] < ((0 | 4) ^ (34 - 34))) {" fullword ascii
    $s5 = "minorInduction[(\"specification\", \"reporter\", \"rocket\", \"write\")](classTablet[(\"type\", \"command\", \"natural\", \"alma" ascii
    $s6 = "defectCamera = (((127) * (0 + 2) + (26 ^ 63)), this);" fullword ascii
    $s7 = "cameraIllustration = degradationBazaar[(\"ballast\", \"phenomenon\", \"principle\", \"service\", \"ExpandEnvironmentStrings\")](" ascii
    $s8 = "} catch (objectBomber) {};" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    1 of ($x*) and all of them
}