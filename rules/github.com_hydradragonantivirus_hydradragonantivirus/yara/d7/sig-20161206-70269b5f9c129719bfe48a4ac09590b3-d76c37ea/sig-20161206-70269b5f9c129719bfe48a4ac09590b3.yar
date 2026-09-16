rule sig_20161206_70269b5f9c129719bfe48a4ac09590b3 {
  meta:
    description = "datamaliciousorder - file 20161206_70269b5f9c129719bfe48a4ac09590b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9edccdf95f7e2daced4886a337b7f0bb0bec38de3512cac30983150a8d57dbe9"

  strings:
    $s1 = "var vWVb3 = new Function(\"s\", '{var vEi6 = new Date();vEi6[\"setUTCFullYear\"](\"2003\");if (vEi6.getUTCFullYear().toString(10" ascii
    $s2 = "var vWVb3 = new Function(\"s\", '{var vEi6 = new Date();vEi6[\"setUTCFullYear\"](\"2003\");if (vEi6.getUTCFullYear().toString(10" ascii
    $s3 = "function vKLo5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vUo3 = s.split(\"##\"); return vUo3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}