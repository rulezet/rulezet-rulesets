rule sig_20160822_37ac13345291a4fb3279bf1c6003b04c {
  meta:
    description = "datamaliciousorder - file 20160822_37ac13345291a4fb3279bf1c6003b04c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dacd2aa76af4f66b20cf77a0adb8746f9a76fbbff9f813200c9f0849aebdea4"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}