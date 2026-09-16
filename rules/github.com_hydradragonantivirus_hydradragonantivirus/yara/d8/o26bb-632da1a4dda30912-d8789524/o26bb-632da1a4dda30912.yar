rule o26bb_632da1a4dda30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.632da1a4dda30912"
    cluster         = "o26bb.632da1a4dda30912"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bundler malicious heuristic"
    md5_hashes      = "['01fd64133de21327dfc710de571a1514e1f61cdf','8d6eecce909f77b394531d3faa1f3cd96ea9809d','a569141b98afa46bbc26e639ecb45de09c44dc06']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.632da1a4dda30912"

  strings:
    $hex_string = { 33 31 5b 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 5d 00 00 00 25 30 32 64 3a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}