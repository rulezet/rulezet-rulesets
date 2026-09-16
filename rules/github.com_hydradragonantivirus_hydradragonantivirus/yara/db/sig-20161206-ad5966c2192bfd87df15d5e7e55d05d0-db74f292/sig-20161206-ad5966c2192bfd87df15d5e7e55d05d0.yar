rule sig_20161206_ad5966c2192bfd87df15d5e7e55d05d0 {
  meta:
    description = "datamaliciousorder - file 20161206_ad5966c2192bfd87df15d5e7e55d05d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "626b55cc3734713788896d1d11ac8d29faa9c650abe1d9e570331d504e867163"

  strings:
    $s1 = "var vAk3 = new Function(\"s\", '{var vCv5 = new Date();vCv5[\"setUTCFullYear\"](\"2003\");if (vCv5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAk3 = new Function(\"s\", '{var vCv5 = new Date();vCv5[\"setUTCFullYear\"](\"2003\");if (vCv5.getUTCFullYear().toString(10)" ascii
    $s3 = "function vKXj9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vPLb0 = s.split(\"##\"); return vPLb0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}