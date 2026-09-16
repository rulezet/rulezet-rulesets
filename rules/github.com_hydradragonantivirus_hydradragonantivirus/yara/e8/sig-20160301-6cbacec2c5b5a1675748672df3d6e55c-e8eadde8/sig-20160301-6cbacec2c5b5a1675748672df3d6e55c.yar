rule sig_20160301_6cbacec2c5b5a1675748672df3d6e55c {
  meta:
    description = "datamaliciousorder - file 20160301_6cbacec2c5b5a1675748672df3d6e55c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5e129f4eeedfd3d5c53c8f4a0391954820ad2df6fed41a07d3df07cbe316cf7"

  strings:
    $s1 = "objectNet = angelGuard[(\"hobby\", \"shorts\", \"ExpandEnvironmentStrings\")]((\"press\", \"trajectory\", \"%TEMP%/\")) + (\"han" ascii
    $s2 = "objectNet = angelGuard[(\"hobby\", \"shorts\", \"ExpandEnvironmentStrings\")]((\"press\", \"trajectory\", \"%TEMP%/\")) + (\"han" ascii
    $s3 = "while(acrobatIndustry[(\"readystate\")] < ((2 ^ 6))) {" fullword ascii
    $s4 = "sumSum = ((72, 277), this);" fullword ascii
    $s5 = "} catch(publicationTonic) {};" fullword ascii
    $s6 = "sumSum[(\"radical\", function String.prototype.reactionHospital() {" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    all of them
}