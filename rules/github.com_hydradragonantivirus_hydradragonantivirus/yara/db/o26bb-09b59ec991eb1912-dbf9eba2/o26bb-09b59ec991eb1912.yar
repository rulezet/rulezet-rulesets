rule o26bb_09b59ec991eb1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.09b59ec991eb1912"
    cluster         = "o26bb.09b59ec991eb1912"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious softcnapp"
    md5_hashes      = "['a77ef01f4440bee867a80412102755bfc0c0d17e','5c60463015b0d429748c5147f2e8b5bd0d03136c','77be0e383d6518210951369f60b05d1a56b9a960']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.09b59ec991eb1912"

  strings:
    $hex_string = { 0f b6 c3 50 e8 f5 13 07 00 83 c4 04 85 c0 75 0a 80 fb 0a 74 05 80 fb 0d 75 12 8b 46 20 47 3b 38 72 da 8b 06 8b ce 6a 01 ff 10 eb 5f 8b 4d f0 eb 54 b8 0c 95 5d 00 8b d7 2b d0 66 90 8a 08 84 c9 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}