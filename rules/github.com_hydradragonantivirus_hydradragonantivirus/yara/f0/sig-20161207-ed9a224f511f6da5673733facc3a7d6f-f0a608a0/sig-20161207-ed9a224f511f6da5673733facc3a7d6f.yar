rule sig_20161207_ed9a224f511f6da5673733facc3a7d6f {
  meta:
    description = "datamaliciousorder - file 20161207_ed9a224f511f6da5673733facc3a7d6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56e38e27daf4792b432c0c6da1ee3de6b43e503eb8fd43b8bbe2361a72516420"

  strings:
    $s1 = "var vFw1 = new Function(\"vXx6\", '{var vMYp6 = new Date();vMYp6[\"setUTCFullYear\"](\"2003\");if (vMYp6.getUTCFullYear().toStri" ascii
    $s2 = "var vFw1 = new Function(\"vXx6\", '{var vMYp6 = new Date();vMYp6[\"setUTCFullYear\"](\"2003\");if (vMYp6.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vMr4 = vXx6.split(\"###\"); return vMr4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBHc8 = new Function(\"vXx6\", '{return vXx6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}