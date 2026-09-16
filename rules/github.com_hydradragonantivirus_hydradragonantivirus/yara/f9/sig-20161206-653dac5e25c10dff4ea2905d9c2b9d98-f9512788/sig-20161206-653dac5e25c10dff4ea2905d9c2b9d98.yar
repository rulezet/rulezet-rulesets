rule sig_20161206_653dac5e25c10dff4ea2905d9c2b9d98 {
  meta:
    description = "datamaliciousorder - file 20161206_653dac5e25c10dff4ea2905d9c2b9d98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27623148d18794c725eda8c0e5414a22a4a529a7e18935b8b83dc8cd7b3372d4"

  strings:
    $s1 = "var vBEo7 = new Function(\"s\", '{var vQg5 = new Date();vQg5[\"setUTCFullYear\"](\"2003\");if (vQg5.getUTCFullYear().toString(10" ascii
    $s2 = "var vBEo7 = new Function(\"s\", '{var vQg5 = new Date();vQg5[\"setUTCFullYear\"](\"2003\");if (vQg5.getUTCFullYear().toString(10" ascii
    $s3 = "function vVm4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vTh1 = s.split(\"##\"); return vTh1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}