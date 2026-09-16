rule sig_20160824_1f5912c9202ffd2d57e6da21ec39a8b3 {
  meta:
    description = "datamaliciousorder - file 20160824_1f5912c9202ffd2d57e6da21ec39a8b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0df40c388829aac6b7ff399971b5fca344d7617896ac7d42029093d85e17506f"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}