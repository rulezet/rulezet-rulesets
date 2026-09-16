rule sig_20161207_cbd69016ec1ba665c5f183ac51671fc1 {
  meta:
    description = "datamaliciousorder - file 20161207_cbd69016ec1ba665c5f183ac51671fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a62a055e72b3e30fe983c24c685654610c95b2a01744ae8f1656d287481d47a"

  strings:
    $s1 = "var vXh4 = new Function(\"vAIy3\", '{var vTHp3 = new Date();vTHp3[\"setUTCFullYear\"](\"2003\");if (vTHp3.getUTCFullYear().toStr" ascii
    $s2 = "var vXh4 = new Function(\"vAIy3\", '{var vTHp3 = new Date();vTHp3[\"setUTCFullYear\"](\"2003\");if (vTHp3.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vBYt7 = vAIy3.split(\"###\"); return vBYt7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vHb5 = new Function(\"vAIy3\", '{return vAIy3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}