rule sig_20160525_37ef3905faa8eb9d46b5e16d714b4ae7 {
  meta:
    description = "datamaliciousorder - file 20160525_37ef3905faa8eb9d46b5e16d714b4ae7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd7f7d97591868084dc13cc2b7d0893e9495de24021ec8d12ee072486f93c4cd"

  strings:
    $s1 = "(rerednerl noitcnuf;};tsilslianbmuhtol nruter{)tsilslianbmuhtol(ssorcal noitcnuf\\n;\"n56x\\\\po\" = gsmm rav\\n;\"56x\\\\py47x" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}