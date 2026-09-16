rule sig_20161206_b00cff19db4ec1509524ee7be2c735a6 {
  meta:
    description = "datamaliciousorder - file 20161206_b00cff19db4ec1509524ee7be2c735a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d6bcf57a2a12bc6dbcea8ff07c79ac99515ec77330ccb22e858b15e13d60baf"

  strings:
    $s1 = "var vJk7 = new Function(\"s\", '{var vHWv2 = new Date();vHWv2[\"setUTCFullYear\"](\"2003\");if (vHWv2.getUTCFullYear().toString(" ascii
    $s2 = "var vJk7 = new Function(\"s\", '{var vHWv2 = new Date();vHWv2[\"setUTCFullYear\"](\"2003\");if (vHWv2.getUTCFullYear().toString(" ascii
    $s3 = "function vVs1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vRWf5 = s.split(\"##\"); return vRWf5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}