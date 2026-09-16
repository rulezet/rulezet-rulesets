rule p26bb_139a93c9cc000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.139a93c9cc000b12"
    cluster         = "p26bb.139a93c9cc000b12"
    cluster_size    = "32"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "ursu malicious heuristic"
    md5_hashes      = "['13bbcd5b904da58d0fd7ee110611232c010be7a5','13d3c6dc39195a5595e83ec799be469972f3c84a','73d878d450ec53e89b6bdc57ba78169e3fd3581d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.139a93c9cc000b12"

  strings:
    $hex_string = { df 93 2e f9 6a b7 57 99 0c 78 e8 b1 1d 16 d8 86 88 04 29 97 3b 05 96 30 01 f7 10 43 fe 69 65 1f ae ac 6f d6 ff d0 5a d5 dd 58 e3 1c f3 c1 54 a3 a5 5b a8 2f ea 23 67 ad e4 4e 9a 3e 19 53 56 bb }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}