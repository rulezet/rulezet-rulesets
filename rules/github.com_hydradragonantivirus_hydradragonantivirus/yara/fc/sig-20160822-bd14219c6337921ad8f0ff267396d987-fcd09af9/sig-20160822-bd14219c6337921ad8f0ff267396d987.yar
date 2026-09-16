rule sig_20160822_bd14219c6337921ad8f0ff267396d987 {
  meta:
    description = "datamaliciousorder - file 20160822_bd14219c6337921ad8f0ff267396d987.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ca4dfb453ed71c64417e30249f493941d038f0c5775c6d5dd802b2e3ef57710"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}