rule sig_20161207_bc74e583b470ab5f7c789120a17eab16 {
  meta:
    description = "datamaliciousorder - file 20161207_bc74e583b470ab5f7c789120a17eab16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee34cc4745f88177dfc96fb9e7fee1e5cd0bf02bd295b2aef8ce17335a154fc7"

  strings:
    $s1 = "var vWl0 = new Function(\"vPd1\", '{var vCHz3 = new Date();vCHz3[\"setUTCFullYear\"](\"2003\");if (vCHz3.getUTCFullYear().toStri" ascii
    $s2 = "var vWl0 = new Function(\"vPd1\", '{var vCHz3 = new Date();vCHz3[\"setUTCFullYear\"](\"2003\");if (vCHz3.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vDCx9 = vPd1.split(\"###\"); return vDCx9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vXn7 = new Function(\"vPd1\", '{return vPd1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}