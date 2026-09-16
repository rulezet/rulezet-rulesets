rule sig_20160526_d79985e93f87c42984da1a11a7037319 {
  meta:
    description = "datamaliciousorder - file 20160526_d79985e93f87c42984da1a11a7037319.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfddbc35e323273255a10ae858bf7a9a0662bef82d69555ce8d5a119199b7fcc"

  strings:
    $s1 = "56x\\\\l\" = v9oGCQJTI rav\\n;\"ht76x\\\\n\" = i0pFPSMVM rav\\n;\"s16x\\\\66x\\\\sa\" = m9lVCHLVI rav\\n;\"66x\\\\safd\" = g9kHI" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}