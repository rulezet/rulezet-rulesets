rule _20160921_9b04118eed50c5e7331c4157a5c4dfc8_20160921_a05dfc337c4a_5586 {
  meta:
    description = "datamaliciousorder - from files 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_a05dfc337c4ada28e05759b304eef904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash2       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"

  strings:
    $s1 = "Bz\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function" ascii
    $s2 = "eturn \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(" ascii
    $s3 = "(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";" ascii
    $s4 = "{return \"Xg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Tv\";})()," ascii
    $s5 = "turn \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}