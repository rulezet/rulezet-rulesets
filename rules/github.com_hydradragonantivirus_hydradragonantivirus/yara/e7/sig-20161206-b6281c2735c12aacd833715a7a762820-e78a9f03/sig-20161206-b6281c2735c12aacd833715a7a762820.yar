rule sig_20161206_b6281c2735c12aacd833715a7a762820 {
  meta:
    description = "datamaliciousorder - file 20161206_b6281c2735c12aacd833715a7a762820.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18c8d7541331dae93d346235f6907b4f94973627fd37c5c751241855ae77e059"

  strings:
    $s1 = "function _IDy0(s) {var _DGh8 = new Date();_DGh8.setUTCFullYear(\"2003\");if (_DGh8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IDy0(s) {var _DGh8 = new Date();_DGh8.setUTCFullYear(\"2003\");if (_DGh8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Gx7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}