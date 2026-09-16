rule sig_20161206_ecd05152faf2075c2fbb24c36a1a3c18 {
  meta:
    description = "datamaliciousorder - file 20161206_ecd05152faf2075c2fbb24c36a1a3c18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a068fde7cf9f1fc3ec78ac1957581a84b3dd62aa0678bb2c42e6222daee9f07b"

  strings:
    $s1 = "var vHe5 = new Function(\"s\", '{var vZUm7 = new Date();vZUm7[\"setUTCFullYear\"](\"2003\");if (vZUm7.getUTCFullYear().toString(" ascii
    $s2 = "var vHe5 = new Function(\"s\", '{var vZUm7 = new Date();vZUm7[\"setUTCFullYear\"](\"2003\");if (vZUm7.getUTCFullYear().toString(" ascii
    $s3 = "function vTMm7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vIe2 = s.split(\"##\"); return vIe2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}