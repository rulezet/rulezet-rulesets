rule sig_20160822_7e645c2c6cc143ebe761355308b1458c {
  meta:
    description = "datamaliciousorder - file 20160822_7e645c2c6cc143ebe761355308b1458c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c967f2447ac0f2a8ae8afad2b1478b4f1a0d7392ebc62e5f7cadc20e6203bb5"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}