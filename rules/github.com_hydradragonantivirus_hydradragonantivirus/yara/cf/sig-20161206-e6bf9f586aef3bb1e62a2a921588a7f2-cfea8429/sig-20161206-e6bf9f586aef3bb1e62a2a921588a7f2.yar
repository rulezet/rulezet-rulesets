rule sig_20161206_e6bf9f586aef3bb1e62a2a921588a7f2 {
  meta:
    description = "datamaliciousorder - file 20161206_e6bf9f586aef3bb1e62a2a921588a7f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fc7dc2de254d5b65650cc5a58a82c1d604d24f94fbe6ab44b0b7d7a36482be9"

  strings:
    $s1 = "var vUr1 = new Function(\"s\", '{var vNRk8 = new Date();vNRk8[\"setUTCFullYear\"](\"2003\");if (vNRk8.getUTCFullYear().toString(" ascii
    $s2 = "var vUr1 = new Function(\"s\", '{var vNRk8 = new Date();vNRk8[\"setUTCFullYear\"](\"2003\");if (vNRk8.getUTCFullYear().toString(" ascii
    $s3 = "function vFTi9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vLOs6 = s.split(\"##\"); return vLOs6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}