rule sig_20161206_7051e45f8094197a46aa3a3d4d8389ae {
  meta:
    description = "datamaliciousorder - file 20161206_7051e45f8094197a46aa3a3d4d8389ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163c6aa92334871d12449accbb18cee1e72dbdffee2ee18ee70008b3d371098b"

  strings:
    $s1 = "var vAc6 = new Function(\"s\", '{var vHc2 = new Date();vHc2[\"setUTCFullYear\"](\"2003\");if (vHc2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAc6 = new Function(\"s\", '{var vHc2 = new Date();vHc2[\"setUTCFullYear\"](\"2003\");if (vHc2.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vFXq6 = s.split(\"##\"); return vFXq6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vFe1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}