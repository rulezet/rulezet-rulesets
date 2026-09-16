rule pfc8_1b106920d3d30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.1b106920d3d30912"
    cluster         = "pfc8.1b106920d3d30912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "drolock riskware androidos"
    md5_hashes      = "['9b0d1ef404a0fff31f000522f5869088abf6a731','893b7c40134381f4bfe8b7f79f50c73febb6f4fc','47f92b47e267dda9e29b79568f402dd776195768']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.1b106920d3d30912"

  strings:
    $hex_string = { 50 a2 f9 e7 c9 18 86 68 b2 e5 3b 06 1d b9 a6 47 a8 fe 29 7e 42 4d 59 7c 51 27 55 65 52 8c a0 b0 44 af 4e 56 30 35 07 5c d6 71 ac 13 ad db e4 3e c8 8d b7 53 05 f5 14 67 7a aa ba 7f 32 80 d3 ed }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}