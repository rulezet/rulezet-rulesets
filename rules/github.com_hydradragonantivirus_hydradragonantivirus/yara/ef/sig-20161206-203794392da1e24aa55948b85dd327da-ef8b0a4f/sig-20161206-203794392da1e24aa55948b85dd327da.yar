rule sig_20161206_203794392da1e24aa55948b85dd327da {
  meta:
    description = "datamaliciousorder - file 20161206_203794392da1e24aa55948b85dd327da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbeacb7aeb8932005b709b2217a059830ecb5ab21127fe2aa52f26a01767fdd"

  strings:
    $s1 = "var vXh7 = new Function(\"s\", '{var vAm5 = new Date();vAm5[\"setUTCFullYear\"](\"2003\");if (vAm5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vXh7 = new Function(\"s\", '{var vAm5 = new Date();vAm5[\"setUTCFullYear\"](\"2003\");if (vAm5.getUTCFullYear().toString(10)" ascii
    $s3 = "function vOb9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vMGb6 = s.split(\"##\"); return vMGb6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}