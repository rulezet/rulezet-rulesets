rule sig_20161206_02b7d5ae07af57f20b7a981200559a4b {
  meta:
    description = "datamaliciousorder - file 20161206_02b7d5ae07af57f20b7a981200559a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2c153e2d060244db40d8eb60126c5cda7583b0df39b15917665c847bd28e2e"

  strings:
    $s1 = "var vAk4 = new Function(\"s\", '{var vWw0 = new Date();vWw0[\"setUTCFullYear\"](\"2003\");if (vWw0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAk4 = new Function(\"s\", '{var vWw0 = new Date();vWw0[\"setUTCFullYear\"](\"2003\");if (vWw0.getUTCFullYear().toString(10)" ascii
    $s3 = "function vJTb2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vTd9 = s.split(\"##\"); return vTd9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}