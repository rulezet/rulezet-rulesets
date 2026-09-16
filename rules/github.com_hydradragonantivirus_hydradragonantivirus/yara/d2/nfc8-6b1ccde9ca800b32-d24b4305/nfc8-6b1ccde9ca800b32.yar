rule nfc8_6b1ccde9ca800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.6b1ccde9ca800b32"
    cluster         = "nfc8.6b1ccde9ca800b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "stealer androidos fakeinst"
    md5_hashes      = "['5fef8e4a47feea7b85a99928155e4d64f814695f','525c07c43bdf7f311e910d8781ed20902d6e0fd6','380d873673804fb1a907400121271dcad546b0bb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.6b1ccde9ca800b32"

  strings:
    $hex_string = { db cd 5e 6c c1 84 08 46 b5 88 e3 b6 e2 22 58 15 63 f0 45 bc 0f 11 03 b2 48 98 ae 62 1c e4 73 96 30 29 23 b8 cb a3 ed c8 3a 83 1f c5 21 44 8c 45 2b a1 bf 09 f3 3b be 36 1e c6 7a 1a 3d 7e 86 ee }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}