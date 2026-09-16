rule sig_20160824_e0122416e7c02b7725e61f9895bdd1a7 {
  meta:
    description = "datamaliciousorder - file 20160824_e0122416e7c02b7725e61f9895bdd1a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68bbda2531ba24e6393e58276cd20fafe37e17a4501f5b1fc243fb8c35124063"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}