rule sig_20161206_55607220680be95d0cf54c3425290008 {
  meta:
    description = "datamaliciousorder - file 20161206_55607220680be95d0cf54c3425290008.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0ed604c4f26b5f9de72e1d0f4ad074120dc4ae9447e72aed626ab2cc59b9f90"

  strings:
    $s1 = "var vAg9 = new Function(\"s\", '{var vWFm6 = new Date();vWFm6[\"setUTCFullYear\"](\"2003\");if (vWFm6.getUTCFullYear().toString(" ascii
    $s2 = "var vAg9 = new Function(\"s\", '{var vWFm6 = new Date();vWFm6[\"setUTCFullYear\"](\"2003\");if (vWFm6.getUTCFullYear().toString(" ascii
    $s3 = "function vYy6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vSDi0 = s.split(\"##\"); return vSDi0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}