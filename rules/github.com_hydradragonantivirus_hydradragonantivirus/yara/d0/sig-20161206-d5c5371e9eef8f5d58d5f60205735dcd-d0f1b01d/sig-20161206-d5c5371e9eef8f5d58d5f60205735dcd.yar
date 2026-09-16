rule sig_20161206_d5c5371e9eef8f5d58d5f60205735dcd {
  meta:
    description = "datamaliciousorder - file 20161206_d5c5371e9eef8f5d58d5f60205735dcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a8ffa65177186d0d5fa0bd9d2b1325b817dc2dc5609876a2d181521be0175b"

  strings:
    $s1 = "var vTj2 = new Function(\"s\", '{var vBf5 = new Date();vBf5[\"setUTCFullYear\"](\"2003\");if (vBf5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vTj2 = new Function(\"s\", '{var vBf5 = new Date();vBf5[\"setUTCFullYear\"](\"2003\");if (vBf5.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vLKh4 = s.split(\"##\"); return vLKh4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vBu5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}