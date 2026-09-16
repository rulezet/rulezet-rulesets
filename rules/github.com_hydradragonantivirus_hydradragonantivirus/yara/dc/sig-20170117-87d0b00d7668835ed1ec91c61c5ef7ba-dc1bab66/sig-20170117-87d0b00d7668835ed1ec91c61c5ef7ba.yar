rule sig_20170117_87d0b00d7668835ed1ec91c61c5ef7ba {
  meta:
    description = "datamaliciousorder - file 20170117_87d0b00d7668835ed1ec91c61c5ef7ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e176c60af5f6405c6ae4fa044c7c5a55fa5d8f73eb0fad7fe542f16b21dd7d6"

  strings:
    $s1 = "var umlejib09 = new Function(afenxyxgumzisimatozzefgamolmusigledqurzitixeferxulifukezkezwufimlaqkuhiruwpavufydtozamolegmuvnikbu[" ascii
    $s2 = "var umlejib09 = new Function(afenxyxgumzisimatozzefgamolmusigledqurzitixeferxulifukezkezwufimlaqkuhiruwpavufydtozamolegmuvnikbu[" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}