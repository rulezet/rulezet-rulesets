rule sig_20161205_ab7c86aa85de919efb93ffd1c3db8469 {
  meta:
    description = "datamaliciousorder - file 20161205_ab7c86aa85de919efb93ffd1c3db8469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf93f6bd597099016eec734a1bfd0ed27a2407878d6977f4de224f7536f2f0fb"

  strings:
    $s1 = "function _GGu3(s) {var _Tu5 = new Date();_Tu5.setUTCFullYear(\"2003\");if (_Tu5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GGu3(s) {var _Tu5 = new Date();_Tu5.setUTCFullYear(\"2003\");if (_Tu5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _NGu4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}