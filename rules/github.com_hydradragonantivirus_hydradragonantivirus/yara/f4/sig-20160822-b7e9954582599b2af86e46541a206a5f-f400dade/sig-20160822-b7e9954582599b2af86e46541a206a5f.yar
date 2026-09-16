rule sig_20160822_b7e9954582599b2af86e46541a206a5f {
  meta:
    description = "datamaliciousorder - file 20160822_b7e9954582599b2af86e46541a206a5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e4265504447dc0d31f87e8654fb7852b528861dc492d30fed8a02fc46aa38cf"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}