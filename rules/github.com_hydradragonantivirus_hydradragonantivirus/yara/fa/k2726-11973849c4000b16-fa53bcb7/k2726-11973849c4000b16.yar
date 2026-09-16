rule k2726_11973849c4000b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2726.11973849c4000b16"
    cluster         = "k2726.11973849c4000b16"
    cluster_size    = "492"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zusy patched malicious"
    md5_hashes      = "['5e1c44778c1c857a5b9a5963e93447f13fbf5f1a','62d3bfed25aca17e01ee3b6ec5938a70b5207c45','761c34d322a6ddbc931c90f42247a1d9d8e22248']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2726.11973849c4000b16"

  strings:
    $hex_string = { 04 00 00 50 ff 15 74 10 9c 71 66 3d 01 04 1b c0 83 e0 02 89 46 04 83 c7 08 33 c0 ab 5e ab 33 c0 5b 5f 5d c2 0c 00 90 90 90 90 90 8b ff 55 8b ec 51 51 8b 45 18 53 56 57 6a 04 59 3b c1 0f 84 d1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}