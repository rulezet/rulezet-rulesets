rule ofc8_5b1a82d0d6c30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.5b1a82d0d6c30912"
    cluster         = "ofc8.5b1a82d0d6c30912"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos rootnik shuame"
    md5_hashes      = "['2ccabc8d644198aa4d56f37c3de78fa2a0453c4f','312c6b3367d2d173e8bcca8bb1344a58b644ce4a','821f9b05e96c845dda3d45ab8b5ee77f5f9cd8c0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.5b1a82d0d6c30912"

  strings:
    $hex_string = { 83 46 ba e1 d5 6f 82 c1 61 9a 85 45 f3 66 8a e8 54 b7 db 0f 96 c7 f5 72 c2 fd 53 aa 88 5b 27 ee e7 a9 e2 df 7f 2d 01 7b d1 30 1a c4 f0 95 7a 8f 87 ed 26 9d a2 43 02 b0 7e 74 fc c3 5a 84 94 ce }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}