rule sig_20161205_26744f61fc95fde0682afd781af8fcd3 {
  meta:
    description = "datamaliciousorder - file 20161205_26744f61fc95fde0682afd781af8fcd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ac7da8983bee5277e514d3c5144edcfe40db322167dbdd8ee6e72281b32688d"

  strings:
    $s1 = "function _EWg4(s) {var _PHc6 = new Date();_PHc6.setUTCFullYear(\"2003\");if (_PHc6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EWg4(s) {var _PHc6 = new Date();_PHc6.setUTCFullYear(\"2003\");if (_PHc6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _UZy3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}