rule sig_20161207_582abd669915953bbbb9c8a031a96714 {
  meta:
    description = "datamaliciousorder - file 20161207_582abd669915953bbbb9c8a031a96714.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6655c87b4f216c20d1545de65f8ff3e9b6975151c58b0569181e851aa2f2c703"

  strings:
    $s1 = "var vJWj9 = new Function(\"vMFn2\", '{var vJl3 = new Date();vJl3[\"setUTCFullYear\"](\"2003\");if (vJl3.getUTCFullYear().toStrin" ascii
    $s2 = "var vJWj9 = new Function(\"vMFn2\", '{var vJl3 = new Date();vJl3[\"setUTCFullYear\"](\"2003\");if (vJl3.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vLXw5 = vMFn2.split(\"###\"); return vLXw5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vAGs0 = new Function(\"vMFn2\", '{return vMFn2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}