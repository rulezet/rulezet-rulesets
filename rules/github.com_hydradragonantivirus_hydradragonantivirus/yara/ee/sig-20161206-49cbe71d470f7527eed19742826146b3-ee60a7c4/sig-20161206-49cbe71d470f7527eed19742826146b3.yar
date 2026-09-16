rule sig_20161206_49cbe71d470f7527eed19742826146b3 {
  meta:
    description = "datamaliciousorder - file 20161206_49cbe71d470f7527eed19742826146b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e69597480cedd539184b092e16f699e971781e14b2092a5b6c8497c3266842d7"

  strings:
    $s1 = "var vWPe7 = new Function(\"s\", '{var vDk9 = new Date();vDk9[\"setUTCFullYear\"](\"2003\");if (vDk9.getUTCFullYear().toString(10" ascii
    $s2 = "var vWPe7 = new Function(\"s\", '{var vDk9 = new Date();vDk9[\"setUTCFullYear\"](\"2003\");if (vDk9.getUTCFullYear().toString(10" ascii
    $s3 = "function vXIt5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vBLu3 = s.split(\"##\"); return vBLu3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}