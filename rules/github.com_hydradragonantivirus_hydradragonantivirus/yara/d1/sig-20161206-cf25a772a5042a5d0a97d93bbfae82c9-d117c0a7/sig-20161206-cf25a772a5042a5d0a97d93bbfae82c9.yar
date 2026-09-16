rule sig_20161206_cf25a772a5042a5d0a97d93bbfae82c9 {
  meta:
    description = "datamaliciousorder - file 20161206_cf25a772a5042a5d0a97d93bbfae82c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a22c505e000e71c83965143ed3573884176e86b19c7832c78d141e706d776bd"

  strings:
    $s1 = "var vRu0 = new Function(\"s\", '{var vLIn2 = new Date();vLIn2[\"setUTCFullYear\"](\"2003\");if (vLIn2.getUTCFullYear().toString(" ascii
    $s2 = "var vRu0 = new Function(\"s\", '{var vLIn2 = new Date();vLIn2[\"setUTCFullYear\"](\"2003\");if (vLIn2.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vIo4 = s.split(\"##\"); return vIo4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vLa0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}