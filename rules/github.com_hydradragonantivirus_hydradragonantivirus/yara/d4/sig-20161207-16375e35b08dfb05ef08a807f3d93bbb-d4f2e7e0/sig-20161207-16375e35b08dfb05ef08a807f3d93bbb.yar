rule sig_20161207_16375e35b08dfb05ef08a807f3d93bbb {
  meta:
    description = "datamaliciousorder - file 20161207_16375e35b08dfb05ef08a807f3d93bbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03897cc59e7945f4693246e523a60e172bda3f70c6e81cd8850041c54d20a336"

  strings:
    $s1 = "var vOf5 = new Function(\"vHq9\", '{var vEOl3 = new Date();vEOl3[\"setUTCFullYear\"](\"2003\");if (vEOl3.getUTCFullYear().toStri" ascii
    $s2 = "var vOf5 = new Function(\"vHq9\", '{var vEOl3 = new Date();vEOl3[\"setUTCFullYear\"](\"2003\");if (vEOl3.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vMr3 = vHq9.split(\"###\"); return vMr3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGJa8 = new Function(\"vHq9\", '{return vHq9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}