rule o26d7_5bb29a58d78bdb12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d7.5bb29a58d78bdb12"
    cluster         = "o26d7.5bb29a58d78bdb12"
    cluster_size    = "30"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "soft barys malicious"
    md5_hashes      = "['6fe9a1810aab4076ce2adbc695d2760127a809f5','3af67ac9add283a408e5ca9e3b24f3595ba3a780','c62e2b1e2adae67c0978dc12638255e1d512396f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d7.5bb29a58d78bdb12"

  strings:
    $hex_string = { fc e8 b6 1e fb ff c3 e9 fc db fa ff eb d3 5f 5e 5b 8b e5 5d c2 04 00 00 d8 53 32 b0 20 77 68 4b b1 0a e3 e7 9b 91 ec d3 17 5f 39 d0 aa 52 15 45 93 a5 5b 29 2f 03 aa 7b 8a ea 5d 28 65 b8 d1 11 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}