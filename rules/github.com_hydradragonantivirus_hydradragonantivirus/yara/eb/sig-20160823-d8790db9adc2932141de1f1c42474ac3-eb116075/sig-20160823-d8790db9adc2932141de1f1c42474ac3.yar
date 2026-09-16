rule sig_20160823_d8790db9adc2932141de1f1c42474ac3 {
  meta:
    description = "datamaliciousorder - file 20160823_d8790db9adc2932141de1f1c42474ac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e49cdeef3854275dba18725d89f4df89ec0e5341113da560214d9e664207dfb8"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}