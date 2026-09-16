rule sig_20160301_622c43055af57700af6295953a60c21b {
  meta:
    description = "datamaliciousorder - file 20160301_622c43055af57700af6295953a60c21b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b1c7df1c02c3ef2dad84451f77323d4919aca331b8d2695a32042a6d3c5c99"

  strings:
    $x1 = "criteriaNorm = versionAdministration[(\"information\", \"discrete\", \"vacuum\", \"extract\", \"ExpandEnvironmentStrings\")]((\"" ascii
    $x2 = "\", \"attribute\", \"emotion\", \"%TEMP%/\")) + (\"portTrilogy\") + (\"imitate\", \"director\", \"tribune\", \"cycle\", \".scr\"" ascii
    $s3 = "while(portalRepublic[(\"statuette\", \"packing\", \"thesis\", \"command\", \"readystate\")] < ((40 - 38) ^ (([!+[] + !+[]]) * ([" ascii
    $s4 = "while(portalRepublic[(\"statuette\", \"packing\", \"thesis\", \"command\", \"readystate\")] < ((40 - 38) ^ (([!+[] + !+[]]) * ([" ascii
    $s5 = "statisticsEquivalent = ((Math.pow((9 * 13 + 8), (1 * 2)) - (462930 / 30)), this);" fullword ascii
    $s6 = "rotationConfidential[(\"write\")](portalRepublic[(\"modify\", function String.prototype.clientPaste() {" fullword ascii
    $s7 = "criteriaNorm = versionAdministration[(\"information\", \"discrete\", \"vacuum\", \"extract\", \"ExpandEnvironmentStrings\")]((\"" ascii
    $s8 = "} catch(ruinPermanent) {};" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and all of them
}