rule sig_20160823_26de27fe04aca6695f071b2a9ecc9ac3 {
  meta:
    description = "datamaliciousorder - file 20160823_26de27fe04aca6695f071b2a9ecc9ac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "173f1f016c5bb71bbf81b41b82d1433dce2e2873c410c4e03f1ebcfd632450b9"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}