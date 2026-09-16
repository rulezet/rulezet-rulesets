rule k26bb_409048b4ee208912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.409048b4ee208912"
    cluster         = "k26bb.409048b4ee208912"
    cluster_size    = "368"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "attribute filerepmalware heuristic"
    md5_hashes      = "['dc11a04901c316d8ff4c5801ab42da48fc8e2468','043a9e04c6f919a2817c28b1bf09a688b960ab9e','4417216498bd3f3cb0f8aed7f6a9a79cdc6d4fdf']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.409048b4ee208912"

  strings:
    $hex_string = { d0 7e 71 8b 75 f8 8d 45 f3 6a 01 50 ff 75 d0 e8 cb 36 00 00 85 c0 74 5f 39 5d e4 75 21 80 7d 0b 0d 74 2b 80 7d 0b 0a 74 25 8a 45 f3 88 04 3e 46 3a c3 88 45 0b 74 40 3b 75 f4 7c ca eb 39 0f b6 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}