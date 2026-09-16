rule sig_20161206_87cac6f76037ebd01a76959c3c70b1a4 {
  meta:
    description = "datamaliciousorder - file 20161206_87cac6f76037ebd01a76959c3c70b1a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef4250a0a6de1a379e36c8abaeffb7d296d41dfe089f20891efc3b2953ddcfa7"

  strings:
    $s1 = "var vHj4 = new Function(\"s\", '{var vAd1 = new Date();vAd1[\"setUTCFullYear\"](\"2003\");if (vAd1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vHj4 = new Function(\"s\", '{var vAd1 = new Date();vAd1[\"setUTCFullYear\"](\"2003\");if (vAd1.getUTCFullYear().toString(10)" ascii
    $s3 = "function vFb8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vISh2 = s.split(\"##\"); return vISh2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}