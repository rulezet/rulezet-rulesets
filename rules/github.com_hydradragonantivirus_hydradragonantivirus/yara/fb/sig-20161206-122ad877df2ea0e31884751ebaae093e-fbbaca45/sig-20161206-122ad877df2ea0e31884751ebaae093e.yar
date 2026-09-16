rule sig_20161206_122ad877df2ea0e31884751ebaae093e {
  meta:
    description = "datamaliciousorder - file 20161206_122ad877df2ea0e31884751ebaae093e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33c3e8679379eda7d65fb2b73c1c293b09ebf0bc188fdf4a9a253338202e9fdf"

  strings:
    $s1 = "var vTi9 = new Function(\"s\", '{var vLu7 = new Date();vLu7[\"setUTCFullYear\"](\"2003\");if (vLu7.getUTCFullYear().toString(10)" ascii
    $s2 = "var vTi9 = new Function(\"s\", '{var vLu7 = new Date();vLu7[\"setUTCFullYear\"](\"2003\");if (vLu7.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vWj9 = s.split(\"##\"); return vWj9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vCPd2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}