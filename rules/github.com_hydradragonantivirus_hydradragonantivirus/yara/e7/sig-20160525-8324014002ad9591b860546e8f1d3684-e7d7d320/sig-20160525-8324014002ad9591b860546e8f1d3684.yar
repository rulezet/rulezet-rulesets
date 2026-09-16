rule sig_20160525_8324014002ad9591b860546e8f1d3684 {
  meta:
    description = "datamaliciousorder - file 20160525_8324014002ad9591b860546e8f1d3684.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5d0e78abd8ee3ea74e909b6cb56202e658f6cb6ebfd21fcbc71b742a2b6b71c"

  strings:
    $s1 = "setihwxelfj rav;\"4Y4h\" = gedotdarj rav\\n;\"ae27x\\\\C\" = deerdj rav\\n;\"jbf4x\\\\et\" = sdnetj rav\\n;\"c56x\\\\\" = ssorca" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}