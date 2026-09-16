rule sig_20161206_e97026299e965a3243830afcc4c2d4fc {
  meta:
    description = "datamaliciousorder - file 20161206_e97026299e965a3243830afcc4c2d4fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a92d921b82fb1f690040b9b0725fc6dc26e12af90cfb7e84e2799dbd53cfde18"

  strings:
    $s1 = "var vIt3 = new Function(\"s\", '{var vNNw9 = new Date();vNNw9[\"setUTCFullYear\"](\"2003\");if (vNNw9.getUTCFullYear().toString(" ascii
    $s2 = "var vIt3 = new Function(\"s\", '{var vNNw9 = new Date();vNNw9[\"setUTCFullYear\"](\"2003\");if (vNNw9.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vGx0 = s.split(\"##\"); return vGx0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYIc5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}