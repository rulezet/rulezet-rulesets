rule sig_20161206_6c55381c714323f1035d6aa687c6b07b {
  meta:
    description = "datamaliciousorder - file 20161206_6c55381c714323f1035d6aa687c6b07b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3a376ab794c85f8b96bd5feac3c865d4b1814007489bbcabec5d95226ee3c99"

  strings:
    $s1 = "var vHr8 = new Function(\"s\", '{var vUOu7 = new Date();vUOu7[\"setUTCFullYear\"](\"2003\");if (vUOu7.getUTCFullYear().toString(" ascii
    $s2 = "var vHr8 = new Function(\"s\", '{var vUOu7 = new Date();vUOu7[\"setUTCFullYear\"](\"2003\");if (vUOu7.getUTCFullYear().toString(" ascii
    $s3 = "function vAZf6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vLx7 = s.split(\"##\"); return vLx7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}