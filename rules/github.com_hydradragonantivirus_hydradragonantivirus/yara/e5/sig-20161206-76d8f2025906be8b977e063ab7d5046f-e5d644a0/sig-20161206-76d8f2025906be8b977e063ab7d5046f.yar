rule sig_20161206_76d8f2025906be8b977e063ab7d5046f {
  meta:
    description = "datamaliciousorder - file 20161206_76d8f2025906be8b977e063ab7d5046f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b0a21a580172a2802254b310829ab4226983348b88ab71c15e642f34004f4f3"

  strings:
    $s1 = "var vFDp4 = new Function(\"s\", '{var vXb9 = new Date();vXb9[\"setUTCFullYear\"](\"2003\");if (vXb9.getUTCFullYear().toString(10" ascii
    $s2 = "var vFDp4 = new Function(\"s\", '{var vXb9 = new Date();vXb9[\"setUTCFullYear\"](\"2003\");if (vXb9.getUTCFullYear().toString(10" ascii
    $s3 = "function vTJy6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vXEq0 = s.split(\"##\"); return vXEq0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}