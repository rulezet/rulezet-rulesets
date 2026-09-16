rule sig_20161206_d07cb3771115fb6edc409dba61064e82 {
  meta:
    description = "datamaliciousorder - file 20161206_d07cb3771115fb6edc409dba61064e82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59981e9e17a11167bdffdccc7c78abec748f1ef4f7bd244c4fe680856123c75b"

  strings:
    $s1 = "var vUe1 = new Function(\"s\", '{var vKk1 = new Date();vKk1[\"setUTCFullYear\"](\"2003\");if (vKk1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vUe1 = new Function(\"s\", '{var vKk1 = new Date();vKk1[\"setUTCFullYear\"](\"2003\");if (vKk1.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vKEz4 = s.split(\"##\"); return vKEz4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vEv8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}