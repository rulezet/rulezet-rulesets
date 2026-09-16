rule sig_20161206_70e69362301fe3aaf051a52efedd5cb6 {
  meta:
    description = "datamaliciousorder - file 20161206_70e69362301fe3aaf051a52efedd5cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1bfeddd4f72a725bfedbcedfa3b72b27ba17622fa0a675c5966e78368b7cb7c"

  strings:
    $s1 = "var vTKr5 = new Function(\"s\", '{var vNTe2 = new Date();vNTe2[\"setUTCFullYear\"](\"2003\");if (vNTe2.getUTCFullYear().toString" ascii
    $s2 = "var vTKr5 = new Function(\"s\", '{var vNTe2 = new Date();vNTe2[\"setUTCFullYear\"](\"2003\");if (vNTe2.getUTCFullYear().toString" ascii
    $s3 = "function vGr1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vGXu1 = s.split(\"##\"); return vGXu1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}