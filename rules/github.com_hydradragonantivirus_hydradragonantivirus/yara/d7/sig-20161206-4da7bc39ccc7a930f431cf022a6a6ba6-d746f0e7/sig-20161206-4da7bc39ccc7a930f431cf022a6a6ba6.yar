rule sig_20161206_4da7bc39ccc7a930f431cf022a6a6ba6 {
  meta:
    description = "datamaliciousorder - file 20161206_4da7bc39ccc7a930f431cf022a6a6ba6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fa732ccacfdca0b2d00b4299abaf633bf2b152b5108e5ed8b9d20d390bf77b4"

  strings:
    $s1 = "var vVUg4 = new Function(\"s\", '{var vOu1 = new Date();vOu1[\"setUTCFullYear\"](\"2003\");if (vOu1.getUTCFullYear().toString(10" ascii
    $s2 = "var vVUg4 = new Function(\"s\", '{var vOu1 = new Date();vOu1[\"setUTCFullYear\"](\"2003\");if (vOu1.getUTCFullYear().toString(10" ascii
    $s3 = "function vLg6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vQMf8 = s.split(\"##\"); return vQMf8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}