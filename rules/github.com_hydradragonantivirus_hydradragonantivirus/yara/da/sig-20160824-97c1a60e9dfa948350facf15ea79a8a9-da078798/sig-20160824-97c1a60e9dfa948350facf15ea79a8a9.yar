rule sig_20160824_97c1a60e9dfa948350facf15ea79a8a9 {
  meta:
    description = "datamaliciousorder - file 20160824_97c1a60e9dfa948350facf15ea79a8a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07a5afd0b56732e1098db6efd9c20edc12730e3b9ac9ee9380240075670535c2"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}