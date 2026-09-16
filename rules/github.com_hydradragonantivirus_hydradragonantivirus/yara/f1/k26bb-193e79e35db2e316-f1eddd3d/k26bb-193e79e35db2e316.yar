rule k26bb_193e79e35db2e316 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.193e79e35db2e316"
    cluster         = "k26bb.193e79e35db2e316"
    cluster_size    = "86"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious filerepmalware installcore"
    md5_hashes      = "['4ccdf49f8660da1db71f0352eeab598a0f35cedf','207f0a8b36a2438294df99fd47f749fa1511665a','4c7a322ff87f7408662d7bc8cb5c48c74776d03d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.193e79e35db2e316"

  strings:
    $hex_string = { b0 2d f7 da eb 06 0a e4 74 03 8a c4 aa 92 50 8b dc 33 d2 f7 35 1c 5d 40 00 80 c2 30 88 13 43 49 0b c0 75 ed 0b c9 7f e9 4b 8a 03 aa 3b dc 75 f8 58 c3 e8 1c ff ff ff 8b 55 08 83 fa 12 72 05 ba }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}