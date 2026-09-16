rule sig_20161206_b9608a3d6f26a593b8ce9b1205ef96fd {
  meta:
    description = "datamaliciousorder - file 20161206_b9608a3d6f26a593b8ce9b1205ef96fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a38c294c60dbd5138050cb99fddf7dfb89ca6b7ff8bb8e8a7c6b3348aa0959c"

  strings:
    $s1 = "var vZHz8 = new Function(\"s\", '{var vHg0 = new Date();vHg0[\"setUTCFullYear\"](\"2003\");if (vHg0.getUTCFullYear().toString(10" ascii
    $s2 = "var vZHz8 = new Function(\"s\", '{var vHg0 = new Date();vHg0[\"setUTCFullYear\"](\"2003\");if (vHg0.getUTCFullYear().toString(10" ascii
    $s3 = "function vCQl7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vHDt2 = s.split(\"##\"); return vHDt2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}