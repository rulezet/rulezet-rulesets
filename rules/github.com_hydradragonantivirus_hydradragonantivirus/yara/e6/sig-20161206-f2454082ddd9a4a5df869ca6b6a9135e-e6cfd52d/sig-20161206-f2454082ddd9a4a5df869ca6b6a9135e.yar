rule sig_20161206_f2454082ddd9a4a5df869ca6b6a9135e {
  meta:
    description = "datamaliciousorder - file 20161206_f2454082ddd9a4a5df869ca6b6a9135e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f31def8efa958925337ce2ba764b62e9ec6b698e303908a2dc01aa32189a9f8"

  strings:
    $s1 = "var vIMi0 = new Function(\"s\", '{var vWSt7 = new Date();vWSt7[\"setUTCFullYear\"](\"2003\");if (vWSt7.getUTCFullYear().toString" ascii
    $s2 = "var vIMi0 = new Function(\"s\", '{var vWSt7 = new Date();vWSt7[\"setUTCFullYear\"](\"2003\");if (vWSt7.getUTCFullYear().toString" ascii
    $s3 = "function vNl5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vNYg4 = s.split(\"##\"); return vNYg4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}