rule o26bb_4b163949c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.4b163949c8000b12"
    cluster         = "o26bb.4b163949c8000b12"
    cluster_size    = "2306"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "midie diskwriter crypt"
    md5_hashes      = "['7223de76753ea30fa8967fcba95670106d766d73','e6e2131ff233fd20e58eaffc4485043d3baf91b0','4ebea2b6159b5c1664ef56cae58090223825bf5b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.4b163949c8000b12"

  strings:
    $hex_string = { c1 fb 05 81 e5 1f 00 00 80 57 79 05 4d 83 cd e0 45 8b 74 24 14 39 5e 04 7f 3f 8d 7b 01 3b 7e 08 7f 04 8b c6 eb 0a 57 56 e8 09 fc ff ff 83 c4 08 85 c0 75 05 5f 5e 5d 5b c3 8b 46 04 3b c7 7d 16 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}