rule sig_20160824_3dc88b4b6a231254649f3c8550d36b45 {
  meta:
    description = "datamaliciousorder - file 20160824_3dc88b4b6a231254649f3c8550d36b45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30e4529a42b4022675717d65e8f8bd5d9687aecd20f645fff9b6ccf5260159d3"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}