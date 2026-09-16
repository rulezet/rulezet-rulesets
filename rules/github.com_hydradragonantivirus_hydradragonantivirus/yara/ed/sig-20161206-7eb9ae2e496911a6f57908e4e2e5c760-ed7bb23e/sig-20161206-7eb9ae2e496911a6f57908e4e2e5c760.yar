rule sig_20161206_7eb9ae2e496911a6f57908e4e2e5c760 {
  meta:
    description = "datamaliciousorder - file 20161206_7eb9ae2e496911a6f57908e4e2e5c760.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba17838bcfe8de0eb0d8efff262a1874bc2f26f3a4840749985ee47f2f23237a"

  strings:
    $s1 = "var vUo6 = new Function(\"s\", '{var vQp2 = new Date();vQp2[\"setUTCFullYear\"](\"2003\");if (vQp2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vUo6 = new Function(\"s\", '{var vQp2 = new Date();vQp2[\"setUTCFullYear\"](\"2003\");if (vQp2.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vCMs1 = s.split(\"##\"); return vCMs1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vDo7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}