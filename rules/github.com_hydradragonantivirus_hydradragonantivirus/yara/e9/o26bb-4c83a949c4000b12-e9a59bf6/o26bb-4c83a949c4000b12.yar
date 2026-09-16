rule o26bb_4c83a949c4000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.4c83a949c4000b12"
    cluster         = "o26bb.4c83a949c4000b12"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dealply malicious clmqn"
    md5_hashes      = "['6d5f75692908048b946903a20e9562f01dd04516','fa916dfa489ff7405b24589e87387370ef3442f5','acf774358365b0fd141a80e481245e1354bd835c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.4c83a949c4000b12"

  strings:
    $hex_string = { 88 c5 d2 60 08 37 00 02 83 7b 9b d0 67 c7 22 60 6a 2d a2 e2 58 15 cc 70 77 13 09 b4 a8 ff 63 ab e8 9e 1d 12 74 9d 23 50 8a 75 81 d9 7e a6 cb d0 74 49 0d bd 01 3d a3 4b 09 7d 32 c3 8d 40 00 9f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}