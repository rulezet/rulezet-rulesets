rule sig_20161207_bf9a667fc8f5f8b51477484d82136721 {
  meta:
    description = "datamaliciousorder - file 20161207_bf9a667fc8f5f8b51477484d82136721.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "272b914eec9b9927dc9175d5e2a4d20f209a21bfd09e3789203eba67fdb9cf30"

  strings:
    $s1 = "var vZh1 = new Function(\"vPd1\", '{var vVz3 = new Date();vVz3[\"setUTCFullYear\"](\"2003\");if (vVz3.getUTCFullYear().toString(" ascii
    $s2 = "var vZh1 = new Function(\"vPd1\", '{var vVz3 = new Date();vVz3[\"setUTCFullYear\"](\"2003\");if (vVz3.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vVLn0 = vPd1.split(\"###\"); return vVLn0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vRAa8 = new Function(\"vPd1\", '{return vPd1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}