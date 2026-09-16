rule sig_20161206_5fa16ace2975ead2b80119cf88e26d37 {
  meta:
    description = "datamaliciousorder - file 20161206_5fa16ace2975ead2b80119cf88e26d37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebce991b54d543db4b9599410e9dc9ea27c2fe47e7dd759a2525613e15750fba"

  strings:
    $s1 = "var vFz1 = new Function(\"s\", '{var vDs1 = new Date();vDs1[\"setUTCFullYear\"](\"2003\");if (vDs1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFz1 = new Function(\"s\", '{var vDs1 = new Date();vDs1[\"setUTCFullYear\"](\"2003\");if (vDs1.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vVVg8 = s.split(\"##\"); return vVVg8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYc0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}