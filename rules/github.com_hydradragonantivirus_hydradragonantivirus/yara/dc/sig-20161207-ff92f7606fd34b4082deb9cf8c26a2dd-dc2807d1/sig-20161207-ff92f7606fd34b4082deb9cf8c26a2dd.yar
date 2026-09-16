rule sig_20161207_ff92f7606fd34b4082deb9cf8c26a2dd {
  meta:
    description = "datamaliciousorder - file 20161207_ff92f7606fd34b4082deb9cf8c26a2dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dcfba56c7dd4420d885c6a894950eaa1fe658df30fa2f203ce2352b108add9b"

  strings:
    $s1 = "var vCSc3 = new Function(\"vPVv8\", '{var vYXv1 = new Date();vYXv1[\"setUTCFullYear\"](\"2003\");if (vYXv1.getUTCFullYear().toSt" ascii
    $s2 = "var vCSc3 = new Function(\"vPVv8\", '{var vYXv1 = new Date();vYXv1[\"setUTCFullYear\"](\"2003\");if (vYXv1.getUTCFullYear().toSt" ascii
    $s3 = "var vJt2 = new Function(\"vPVv8\", '{return vPVv8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vADy2 = vPVv8.split(\"###\"); return vADy2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}