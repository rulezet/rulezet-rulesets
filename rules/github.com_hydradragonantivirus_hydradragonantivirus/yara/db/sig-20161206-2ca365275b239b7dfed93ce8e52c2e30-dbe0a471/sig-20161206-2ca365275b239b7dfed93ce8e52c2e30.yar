rule sig_20161206_2ca365275b239b7dfed93ce8e52c2e30 {
  meta:
    description = "datamaliciousorder - file 20161206_2ca365275b239b7dfed93ce8e52c2e30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52f446ec3f3877253c5d359354bfe586d18067cc3bae3544f680d3a5e55cdb61"

  strings:
    $s1 = "var vVn7 = new Function(\"s\", '{var vAPd4 = new Date();vAPd4[\"setUTCFullYear\"](\"2003\");if (vAPd4.getUTCFullYear().toString(" ascii
    $s2 = "var vVn7 = new Function(\"s\", '{var vAPd4 = new Date();vAPd4[\"setUTCFullYear\"](\"2003\");if (vAPd4.getUTCFullYear().toString(" ascii
    $s3 = "function vCLk3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vDe5 = s.split(\"##\"); return vDe5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}