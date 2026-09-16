rule sig_20160824_7b175da567b6a6f5813fe7d6b451d33e {
  meta:
    description = "datamaliciousorder - file 20160824_7b175da567b6a6f5813fe7d6b451d33e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "639bdb22021e61cb6ed46ef4424e1b4fb85cda12fc36670e02fa87919e360470"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}