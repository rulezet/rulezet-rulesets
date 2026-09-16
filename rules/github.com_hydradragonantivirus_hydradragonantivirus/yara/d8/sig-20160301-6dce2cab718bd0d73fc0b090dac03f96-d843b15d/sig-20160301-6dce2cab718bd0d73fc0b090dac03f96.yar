rule sig_20160301_6dce2cab718bd0d73fc0b090dac03f96 {
  meta:
    description = "datamaliciousorder - file 20160301_6dce2cab718bd0d73fc0b090dac03f96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84cc775d34761e2f653b883abbd6af770001888258baa01cc18bcdc5c0079b85"

  strings:
    $s1 = "principleAnatomy = infinitiveCompress[(\"fortune\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"terror\", function String" ascii
    $s2 = "principleAnatomy = infinitiveCompress[(\"fortune\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"terror\", function String" ascii
    $s3 = "charmTitle = ((((((([!+[] + !+[]]) * ([!+[] + !+[]])) + \"\" + (([+!+[]])))) * ([!+[] + !+[] + !+[]])) - (181 - 112)), this);" fullword ascii
    $s4 = "centArcade = charmTitle[(\"cortege\", \"hall\", \"specific\", \"passion\", \"WScript\")][(\"university\", \"suffix\", \"club\", " ascii
    $s5 = "while(centArcade[(\"readystate\")] < ((2 * 2) + (0 & 1))) {" fullword ascii
    $s6 = "} catch(obligationTheorem) {};" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    all of them
}