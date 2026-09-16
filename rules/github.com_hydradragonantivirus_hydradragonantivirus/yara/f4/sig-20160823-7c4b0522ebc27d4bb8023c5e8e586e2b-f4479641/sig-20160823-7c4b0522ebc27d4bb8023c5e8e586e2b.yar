rule sig_20160823_7c4b0522ebc27d4bb8023c5e8e586e2b {
  meta:
    description = "datamaliciousorder - file 20160823_7c4b0522ebc27d4bb8023c5e8e586e2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4194d41300db0cbf704064da9f30f2e82c0bfcecad2b4746382f9fccf85fb816"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}