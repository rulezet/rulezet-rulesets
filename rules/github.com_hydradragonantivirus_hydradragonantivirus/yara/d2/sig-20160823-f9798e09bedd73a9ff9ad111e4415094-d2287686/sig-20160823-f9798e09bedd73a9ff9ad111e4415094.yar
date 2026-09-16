rule sig_20160823_f9798e09bedd73a9ff9ad111e4415094 {
  meta:
    description = "datamaliciousorder - file 20160823_f9798e09bedd73a9ff9ad111e4415094.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "466f70f8ea321010324b7f9876b37e724b9b014649cb56a2543b1db5b3c3febe"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}