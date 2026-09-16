rule j26f3_435ab509ae210b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26f3.435ab509ae210b12"
    cluster         = "j26f3.435ab509ae210b12"
    cluster_size    = "1673"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = ""
    md5_hashes      = "['6986b7b963ca48b943fe562bd51dd25644b5a929','f97fae63d71c002497641743486e69e3bb76867d','8e9df1c4bacf0caf9d03e7a1ecd10d679cb6046e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26f3.435ab509ae210b12"

  strings:
    $hex_string = { 64 1f 00 01 80 b5 00 02 8d 2f 00 03 86 2c 00 04 7a 0f 00 05 72 ee 00 05 fc 79 00 06 d1 61 00 07 a8 88 00 08 af 16 00 09 b3 02 00 0a af 52 00 0b 8a 24 00 0c 42 38 00 0d 29 77 00 0d fc 75 00 0e }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}