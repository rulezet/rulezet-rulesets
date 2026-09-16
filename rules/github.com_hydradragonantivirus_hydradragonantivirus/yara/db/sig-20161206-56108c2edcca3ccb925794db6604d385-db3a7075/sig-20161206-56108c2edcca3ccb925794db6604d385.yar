rule sig_20161206_56108c2edcca3ccb925794db6604d385 {
  meta:
    description = "datamaliciousorder - file 20161206_56108c2edcca3ccb925794db6604d385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "565a10992c93ffc83f336d61753eb20666fa75153ab319eeb9e717277bd4be08"

  strings:
    $s1 = "var vSEn6 = new Function(\"s\", '{var vUm8 = new Date();vUm8[\"setUTCFullYear\"](\"2003\");if (vUm8.getUTCFullYear().toString(10" ascii
    $s2 = "var vSEn6 = new Function(\"s\", '{var vUm8 = new Date();vUm8[\"setUTCFullYear\"](\"2003\");if (vUm8.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vFLz8 = s.split(\"##\"); return vFLz8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vTTz2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}