rule sig_20160824_bcfb203e89c5aea76674492517221b8a {
  meta:
    description = "datamaliciousorder - file 20160824_bcfb203e89c5aea76674492517221b8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2caa72db2551a8d8c3c2928323ede3e2eeebdc53ee1511e1ec7dbb84283b901b"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}