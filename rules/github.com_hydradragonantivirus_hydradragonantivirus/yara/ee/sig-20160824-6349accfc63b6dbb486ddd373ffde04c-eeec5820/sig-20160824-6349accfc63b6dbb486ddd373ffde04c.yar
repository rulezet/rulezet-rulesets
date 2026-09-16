rule sig_20160824_6349accfc63b6dbb486ddd373ffde04c {
  meta:
    description = "datamaliciousorder - file 20160824_6349accfc63b6dbb486ddd373ffde04c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f4e6fb4b1a90cdfb6f7d5fd082bbb35c57ee7e396c617563d2952b105d47279"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}