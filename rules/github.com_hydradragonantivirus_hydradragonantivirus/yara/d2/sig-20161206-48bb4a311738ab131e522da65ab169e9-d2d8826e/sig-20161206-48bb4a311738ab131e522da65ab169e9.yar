rule sig_20161206_48bb4a311738ab131e522da65ab169e9 {
  meta:
    description = "datamaliciousorder - file 20161206_48bb4a311738ab131e522da65ab169e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "179a2854a01f620271f29cb91c8c7ba751d7f54ea1020d9d9360fa3f9b41a11f"

  strings:
    $s1 = "var vTr7 = new Function(\"s\", '{var vNs5 = new Date();vNs5[\"setUTCFullYear\"](\"2003\");if (vNs5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vTr7 = new Function(\"s\", '{var vNs5 = new Date();vNs5[\"setUTCFullYear\"](\"2003\");if (vNs5.getUTCFullYear().toString(10)" ascii
    $s3 = "function vJCf9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vUq2 = s.split(\"##\"); return vUq2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}