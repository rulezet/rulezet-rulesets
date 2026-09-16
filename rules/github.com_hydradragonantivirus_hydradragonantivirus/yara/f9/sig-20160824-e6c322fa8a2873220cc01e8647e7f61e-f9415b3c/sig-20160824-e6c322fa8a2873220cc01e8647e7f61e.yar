rule sig_20160824_e6c322fa8a2873220cc01e8647e7f61e {
  meta:
    description = "datamaliciousorder - file 20160824_e6c322fa8a2873220cc01e8647e7f61e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0672c25748955f809ce73445d332f5b35e0c1feeaf8fb874d640c87ed2b16b18"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}