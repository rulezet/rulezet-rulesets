rule sig_20160301_6c4f827a53a7f8b1de439ae93c559976 {
  meta:
    description = "datamaliciousorder - file 20160301_6c4f827a53a7f8b1de439ae93c559976.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ade71a2d58b71fe6f470c898eceabaf37ca92cda54886a418a128c51eac8b4b5"

  strings:
    $x1 = "bureauBisexual = combineBarbarian[(\"cardinal\", \"sexual\", \"postscript\", \"ExpandEnvironmentStrings\")]((\"pulse\", \"thermo" ascii
    $s2 = "ternative\", \"gigantic\", \"%TEMP%/\")) + (\"standOrientation\") + (\"cardinal\", \"minimal\", \".scr\");" fullword ascii
    $s3 = "while(epilogueFinish[(\"handicap\", \"incident\", \"selection\", \"industrial\", \"readystate\")] < ((([!+[] + !+[]]) * ([!+[] +" ascii
    $s4 = "while(epilogueFinish[(\"handicap\", \"incident\", \"selection\", \"industrial\", \"readystate\")] < ((([!+[] + !+[]]) * ([!+[] +" ascii
    $s5 = "veteranStudent = ((7 & 7) * (5 ^ 0), this);" fullword ascii
    $s6 = "sumVolcano[(\"combination\", \"compress\", \"reorganize\", \"write\")](epilogueFinish[(\"lady\", \"neutral\", \"caste\", \"resis" ascii
    $s7 = "sumVolcano[(\"composer\", \"inspector\", function String.prototype.hobbyBit() {" fullword ascii
    $s8 = "} catch(provisionIndustry) {};" fullword ascii

  condition:
    uint16(0) == 0x6576 and
    1 of ($x*) and all of them
}