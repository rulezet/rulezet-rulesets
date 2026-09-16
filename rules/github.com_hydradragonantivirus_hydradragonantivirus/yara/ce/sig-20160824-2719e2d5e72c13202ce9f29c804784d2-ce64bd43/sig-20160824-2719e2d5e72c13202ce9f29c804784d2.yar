rule sig_20160824_2719e2d5e72c13202ce9f29c804784d2 {
  meta:
    description = "datamaliciousorder - file 20160824_2719e2d5e72c13202ce9f29c804784d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "167febacc87af9f90a69cb9b8a49089fca8742e48d7b335db35d2746727440c4"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}