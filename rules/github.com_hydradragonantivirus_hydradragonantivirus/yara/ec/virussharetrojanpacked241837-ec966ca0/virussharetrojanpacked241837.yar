rule VirusShareTrojanPacked241837 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPacked241837.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c59eb6d8ac6774b7a93140189e773bed9c57a8c2a42996b72ccd06c543dc678b"

  strings:
    $s1 = "Copyright Klenex 2021" fullword ascii
    $s2 = "Flying Windows" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}