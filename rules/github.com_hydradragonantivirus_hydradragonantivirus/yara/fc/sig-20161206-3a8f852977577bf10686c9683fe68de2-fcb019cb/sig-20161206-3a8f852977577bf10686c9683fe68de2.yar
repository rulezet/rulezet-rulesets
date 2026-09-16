rule sig_20161206_3a8f852977577bf10686c9683fe68de2 {
  meta:
    description = "datamaliciousorder - file 20161206_3a8f852977577bf10686c9683fe68de2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfe1b6f95500e54a8b5ee1cc5fa96ebe164ef8e4b308fe886aaa9367598f4a2e"

  strings:
    $s1 = "var vVFs5 = new Function(\"s\", '{var vGo7 = new Date();vGo7[\"setUTCFullYear\"](\"2003\");if (vGo7.getUTCFullYear().toString(10" ascii
    $s2 = "var vVFs5 = new Function(\"s\", '{var vGo7 = new Date();vGo7[\"setUTCFullYear\"](\"2003\");if (vGo7.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vJCu8 = s.split(\"##\"); return vJCu8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vNj9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}