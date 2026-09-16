rule sig_20161206_d215d08f7fe4ef0d32458b411dbca31f {
  meta:
    description = "datamaliciousorder - file 20161206_d215d08f7fe4ef0d32458b411dbca31f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f382019f20b98ecf28f66739397897e3deb5c936a6865592f193a187e5c03d84"

  strings:
    $s1 = "var vJo4 = new Function(\"s\", '{var vZJc1 = new Date();vZJc1[\"setUTCFullYear\"](\"2003\");if (vZJc1.getUTCFullYear().toString(" ascii
    $s2 = "var vJo4 = new Function(\"s\", '{var vZJc1 = new Date();vZJc1[\"setUTCFullYear\"](\"2003\");if (vZJc1.getUTCFullYear().toString(" ascii
    $s3 = "function vTs9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vGEg9 = s.split(\"##\"); return vGEg9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}