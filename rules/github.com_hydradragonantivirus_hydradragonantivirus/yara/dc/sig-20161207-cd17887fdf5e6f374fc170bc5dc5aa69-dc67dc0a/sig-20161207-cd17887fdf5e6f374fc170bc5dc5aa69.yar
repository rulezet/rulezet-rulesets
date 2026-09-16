rule sig_20161207_cd17887fdf5e6f374fc170bc5dc5aa69 {
  meta:
    description = "datamaliciousorder - file 20161207_cd17887fdf5e6f374fc170bc5dc5aa69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa2cd9fdbd387540d847a29899eb3a38acc3784481accf2703b8c924230f13b7"

  strings:
    $s1 = "var vSe3 = new Function(\"vALa0\", '{var vJHp2 = new Date();vJHp2[\"setUTCFullYear\"](\"2003\");if (vJHp2.getUTCFullYear().toStr" ascii
    $s2 = "var vSe3 = new Function(\"vALa0\", '{var vJHp2 = new Date();vJHp2[\"setUTCFullYear\"](\"2003\");if (vJHp2.getUTCFullYear().toStr" ascii
    $s3 = "var vPo1 = new Function(\"vALa0\", '{return vALa0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vHx7 = vALa0.split(\"###\"); return vHx7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}