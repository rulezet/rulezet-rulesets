rule sig_20160824_2cb96e1fa0f26c3a2c34041112fb3f0a {
  meta:
    description = "datamaliciousorder - file 20160824_2cb96e1fa0f26c3a2c34041112fb3f0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20d7973bd87b1ead59671f51899f77aac414cfb127c73ab4a3f8325d7a2c79c0"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}