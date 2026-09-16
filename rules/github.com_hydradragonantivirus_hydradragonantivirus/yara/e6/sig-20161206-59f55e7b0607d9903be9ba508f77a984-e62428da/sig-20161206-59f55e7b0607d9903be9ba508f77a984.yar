rule sig_20161206_59f55e7b0607d9903be9ba508f77a984 {
  meta:
    description = "datamaliciousorder - file 20161206_59f55e7b0607d9903be9ba508f77a984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926471df1cbc08af81b0b20b31964ddb1fed6ae076c51cd4880df24ffd4131b"

  strings:
    $s1 = "var vVIe0 = new Function(\"s\", '{var vFGm6 = new Date();vFGm6[\"setUTCFullYear\"](\"2003\");if (vFGm6.getUTCFullYear().toString" ascii
    $s2 = "var vVIe0 = new Function(\"s\", '{var vFGm6 = new Date();vFGm6[\"setUTCFullYear\"](\"2003\");if (vFGm6.getUTCFullYear().toString" ascii
    $s3 = "function vOm0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vPWw6 = s.split(\"##\"); return vPWw6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}