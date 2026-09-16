rule sig_20161206_069a59316d0b50a6782b5f432f11874f {
  meta:
    description = "datamaliciousorder - file 20161206_069a59316d0b50a6782b5f432f11874f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73bfdec68d6750017464696f01edf360e3abce64e92c068a13efc556ef2cb5ac"

  strings:
    $s1 = "var vCZa0 = new Function(\"s\", '{var vTAx3 = new Date();vTAx3[\"setUTCFullYear\"](\"2003\");if (vTAx3.getUTCFullYear().toString" ascii
    $s2 = "var vCZa0 = new Function(\"s\", '{var vTAx3 = new Date();vTAx3[\"setUTCFullYear\"](\"2003\");if (vTAx3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vSs9 = s.split(\"##\"); return vSs9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vHu0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}