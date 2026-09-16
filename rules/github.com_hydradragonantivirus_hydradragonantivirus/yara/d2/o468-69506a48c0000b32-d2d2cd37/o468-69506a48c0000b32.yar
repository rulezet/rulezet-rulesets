rule o468_69506a48c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o468.69506a48c0000b32"
    cluster         = "o468.69506a48c0000b32"
    cluster_size    = "108"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "expiro allinone classic"
    md5_hashes      = "['b411dec84ed4aada0057235a5406e5b3b3bd6724','34377f5b6cf5d94ccb043754da3f63ff2b74e30d','0b01166a8f4f7cf1589ed277114f2e744d5b4877']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o468.69506a48c0000b32"

  strings:
    $hex_string = { 44 6f 83 87 95 3b 36 82 39 74 12 d6 6b 8e a4 14 cc 91 76 af 39 7e 13 53 16 19 0b 21 3d 1c f5 58 bd 1b c5 c1 08 b0 3f 5f 7f 11 d5 0a 3a 14 6a 3e e3 eb a4 70 f2 e0 3c f2 37 7b c9 a9 6c b4 e8 8f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}