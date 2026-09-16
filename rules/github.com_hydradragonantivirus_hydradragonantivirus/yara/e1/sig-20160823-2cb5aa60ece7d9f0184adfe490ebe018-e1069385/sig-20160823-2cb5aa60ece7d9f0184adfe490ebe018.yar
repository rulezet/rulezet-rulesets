rule sig_20160823_2cb5aa60ece7d9f0184adfe490ebe018 {
  meta:
    description = "datamaliciousorder - file 20160823_2cb5aa60ece7d9f0184adfe490ebe018.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb063463432ade14849ab2fb53b03c7626b421b2bcf5e96a53b7d4d20705004c"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}