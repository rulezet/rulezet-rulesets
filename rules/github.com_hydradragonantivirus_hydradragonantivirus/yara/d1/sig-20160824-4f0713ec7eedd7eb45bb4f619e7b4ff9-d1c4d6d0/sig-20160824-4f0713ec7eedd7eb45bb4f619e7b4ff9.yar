rule sig_20160824_4f0713ec7eedd7eb45bb4f619e7b4ff9 {
  meta:
    description = "datamaliciousorder - file 20160824_4f0713ec7eedd7eb45bb4f619e7b4ff9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69ee11523bdc582e7ae73bcfe94506c5ec552ac1df19cdd203c72e6f36c0e790"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}