rule sig_20161206_8a64d657ff475d1a8ad196aae0a86435 {
  meta:
    description = "datamaliciousorder - file 20161206_8a64d657ff475d1a8ad196aae0a86435.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b32f91661032d2558a1adb65acaa210079a8c451797b12440495e5f52e8c648"

  strings:
    $s1 = "var vXSa0 = new Function(\"s\", '{var vSu0 = new Date();vSu0[\"setUTCFullYear\"](\"2003\");if (vSu0.getUTCFullYear().toString(10" ascii
    $s2 = "var vXSa0 = new Function(\"s\", '{var vSu0 = new Date();vSu0[\"setUTCFullYear\"](\"2003\");if (vSu0.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vXGh1 = s.split(\"##\"); return vXGh1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vQLq2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}