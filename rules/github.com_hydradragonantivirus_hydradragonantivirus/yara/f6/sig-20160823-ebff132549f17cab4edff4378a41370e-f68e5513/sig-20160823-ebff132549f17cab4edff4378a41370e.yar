rule sig_20160823_ebff132549f17cab4edff4378a41370e {
  meta:
    description = "datamaliciousorder - file 20160823_ebff132549f17cab4edff4378a41370e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d89c02f99a048ec2ea29f05d97bd5cadecdb13458612fa478485b71c908aa00"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}