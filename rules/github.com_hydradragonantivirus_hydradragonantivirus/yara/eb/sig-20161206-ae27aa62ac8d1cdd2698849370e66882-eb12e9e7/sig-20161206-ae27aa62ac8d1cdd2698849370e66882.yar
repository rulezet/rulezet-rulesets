rule sig_20161206_ae27aa62ac8d1cdd2698849370e66882 {
  meta:
    description = "datamaliciousorder - file 20161206_ae27aa62ac8d1cdd2698849370e66882.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d68c0a0a39d590983de3a38a489365d19dbefea990570582bb2dff942c8d0ca3"

  strings:
    $s1 = "var vNw9 = new Function(\"s\", '{var vALs6 = new Date();vALs6[\"setUTCFullYear\"](\"2003\");if (vALs6.getUTCFullYear().toString(" ascii
    $s2 = "var vNw9 = new Function(\"s\", '{var vALs6 = new Date();vALs6[\"setUTCFullYear\"](\"2003\");if (vALs6.getUTCFullYear().toString(" ascii
    $s3 = "function vZi5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vTt1 = s.split(\"##\"); return vTt1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}