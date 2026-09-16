rule sig_20161207_fc6e7d459943b1a794c091ea4f72decb {
  meta:
    description = "datamaliciousorder - file 20161207_fc6e7d459943b1a794c091ea4f72decb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00808a96b592bc555d31918c2588a0363b5c22d506c79da8d8e489f633b25496"

  strings:
    $s1 = "var vEe1 = new Function(\"vXl8\", '{var vUt4 = new Date();vUt4[\"setUTCFullYear\"](\"2003\");if (vUt4.getUTCFullYear().toString(" ascii
    $s2 = "var vEe1 = new Function(\"vXl8\", '{var vUt4 = new Date();vUt4[\"setUTCFullYear\"](\"2003\");if (vUt4.getUTCFullYear().toString(" ascii
    $s3 = "var vAb5 = new Function(\"vXl8\", '{return vXl8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vYh9 = vXl8.split(\"###\"); return vYh9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}