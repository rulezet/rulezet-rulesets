rule sig_20160823_8b279adc8df9433c3440e87fee9f0c7c {
  meta:
    description = "datamaliciousorder - file 20160823_8b279adc8df9433c3440e87fee9f0c7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed4ecb95cb696932f2f6f1b2acbdae27fe94962dec52d5f902d88f1a722a9fb5"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}