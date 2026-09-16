rule sig_20160823_461ae62592a47d51fb841cbbdb16a096 {
  meta:
    description = "datamaliciousorder - file 20160823_461ae62592a47d51fb841cbbdb16a096.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56f796c9e8bd255c8ff0f083a93996e1f684353ef96004844b3ff48edd9e110b"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}