rule sig_20160824_5b6ab14f3ae9ab6062c17c388240a457 {
  meta:
    description = "datamaliciousorder - file 20160824_5b6ab14f3ae9ab6062c17c388240a457.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bfb181727d9e9a69a54ee4e0d14aa35ac6f7e00c7b82d6e7d33adf53b3e6dac"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}