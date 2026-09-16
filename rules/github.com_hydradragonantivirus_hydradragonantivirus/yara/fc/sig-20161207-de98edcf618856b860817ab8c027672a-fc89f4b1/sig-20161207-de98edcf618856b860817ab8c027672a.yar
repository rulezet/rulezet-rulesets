rule sig_20161207_de98edcf618856b860817ab8c027672a {
  meta:
    description = "datamaliciousorder - file 20161207_de98edcf618856b860817ab8c027672a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344f101cd52febadcf06d5be2cfac006a27e78be4276acc1af8048c3b31fa502"

  strings:
    $s1 = "var vAq9 = new Function(\"vILi2\", '{var vIw6 = new Date();vIw6[\"setUTCFullYear\"](\"2003\");if (vIw6.getUTCFullYear().toString" ascii
    $s2 = "var vAq9 = new Function(\"vILi2\", '{var vIw6 = new Date();vIw6[\"setUTCFullYear\"](\"2003\");if (vIw6.getUTCFullYear().toString" ascii
    $s3 = "var vWu1 = new Function(\"vILi2\", '{return vILi2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vPm7 = vILi2.split(\"###\"); return vPm7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}