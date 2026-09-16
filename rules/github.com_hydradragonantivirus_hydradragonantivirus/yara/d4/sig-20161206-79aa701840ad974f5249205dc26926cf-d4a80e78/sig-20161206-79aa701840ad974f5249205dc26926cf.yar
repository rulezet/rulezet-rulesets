rule sig_20161206_79aa701840ad974f5249205dc26926cf {
  meta:
    description = "datamaliciousorder - file 20161206_79aa701840ad974f5249205dc26926cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3513f3b86ec3292bf0c2a7cf8240071966fd955306c2f212fc57aae2096d847b"

  strings:
    $s1 = "var vRBd8 = new Function(\"s\", '{var vBe5 = new Date();vBe5[\"setUTCFullYear\"](\"2003\");if (vBe5.getUTCFullYear().toString(10" ascii
    $s2 = "var vRBd8 = new Function(\"s\", '{var vBe5 = new Date();vBe5[\"setUTCFullYear\"](\"2003\");if (vBe5.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vYr9 = s.split(\"##\"); return vYr9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vCg2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}