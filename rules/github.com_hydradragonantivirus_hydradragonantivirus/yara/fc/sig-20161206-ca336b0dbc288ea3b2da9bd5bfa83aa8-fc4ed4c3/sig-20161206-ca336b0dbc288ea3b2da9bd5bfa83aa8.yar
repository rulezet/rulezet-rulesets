rule sig_20161206_ca336b0dbc288ea3b2da9bd5bfa83aa8 {
  meta:
    description = "datamaliciousorder - file 20161206_ca336b0dbc288ea3b2da9bd5bfa83aa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f2eb714dcebea03747d18970fb51c550dc2aeba7a044c1ca1d81153c6a67011"

  strings:
    $s1 = "var vRSi9 = new Function(\"s\", '{var vJv7 = new Date();vJv7[\"setUTCFullYear\"](\"2003\");if (vJv7.getUTCFullYear().toString(10" ascii
    $s2 = "var vRSi9 = new Function(\"s\", '{var vJv7 = new Date();vJv7[\"setUTCFullYear\"](\"2003\");if (vJv7.getUTCFullYear().toString(10" ascii
    $s3 = "function vDZe8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vILr3 = s.split(\"##\"); return vILr3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}