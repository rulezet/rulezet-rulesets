rule sig_20161205_e1869f568e5f00e613702cc7e2992414 {
  meta:
    description = "datamaliciousorder - file 20161205_e1869f568e5f00e613702cc7e2992414.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0ebf5efcd558d7c5aafd0f6d4f93ef06b66cd6c93faa19b195b13f748e0fa11"

  strings:
    $s1 = "function _LPm1(s) {var _No8 = new Date();_No8.setUTCFullYear(\"2003\");if (_No8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LPm1(s) {var _No8 = new Date();_No8.setUTCFullYear(\"2003\");if (_No8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Mx0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}