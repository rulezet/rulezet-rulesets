rule sig_20161206_cae60dbcdb2a7e2d419a730f3a62ca5d {
  meta:
    description = "datamaliciousorder - file 20161206_cae60dbcdb2a7e2d419a730f3a62ca5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eade412880be82c2d502474297cc44923dbee5f3efdb1b9a9b62c4080f5d8947"

  strings:
    $s1 = "var vPs2 = new Function(\"s\", '{var vMYb9 = new Date();vMYb9[\"setUTCFullYear\"](\"2003\");if (vMYb9.getUTCFullYear().toString(" ascii
    $s2 = "var vPs2 = new Function(\"s\", '{var vMYb9 = new Date();vMYb9[\"setUTCFullYear\"](\"2003\");if (vMYb9.getUTCFullYear().toString(" ascii
    $s3 = "function vMu5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vYMs4 = s.split(\"##\"); return vYMs4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}