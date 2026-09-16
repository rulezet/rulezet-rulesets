rule sig_20160301_57db44ef089296e549152662617da157 {
  meta:
    description = "datamaliciousorder - file 20160301_57db44ef089296e549152662617da157.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eefe0b69ff3d506027ce4cfbb212efb4f1a3530cae4e13bf9e7fade8cd87139"

  strings:
    $s1 = "transplantSphere = sectionDust[(\"trivial\", \"acrobat\", \"motor\", \"structure\", \"ExpandEnvironmentStrings\")]((\"army\", \"" ascii
    $s2 = "marchManifest = (((76 | 51) & (Math.pow(145, 2) - 20900)), this);" fullword ascii
    $s3 = "mechanicAddress = marchManifest[(\"present\", \"degradation\", \"symptom\", \"interpretation\", \"WScript\")][(\"almanac\", \"Cr" ascii
    $s4 = "while(almanacTelevision[(\"colony\", \"technique\", \"cycle\", \"readystate\")] < ((7 & 6) & (1 ^ 4))) {" fullword ascii
    $s5 = "((\"resource\", \"platform\", \"sprint\", \"minor\", function String.prototype.absorptionFocus() {" fullword ascii
    $s6 = "} catch(organBisexual) {};" fullword ascii

  condition:
    uint16(0) == 0x616d and
    all of them
}