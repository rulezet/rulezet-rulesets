rule sig_20161206_9c9f59d033f76efbb63d56a67bff0216 {
  meta:
    description = "datamaliciousorder - file 20161206_9c9f59d033f76efbb63d56a67bff0216.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "859b6db39bef83842e81e883e993858e36f259a9aafe96b2c469eeeb63765ec6"

  strings:
    $s1 = "var vUVu2 = new Function(\"s\", '{var vQr7 = new Date();vQr7[\"setUTCFullYear\"](\"2003\");if (vQr7.getUTCFullYear().toString(10" ascii
    $s2 = "var vUVu2 = new Function(\"s\", '{var vQr7 = new Date();vQr7[\"setUTCFullYear\"](\"2003\");if (vQr7.getUTCFullYear().toString(10" ascii
    $s3 = "function vCMt4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vFSs2 = s.split(\"##\"); return vFSs2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}