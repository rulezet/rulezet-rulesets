rule k26d4_13a96926df193912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d4.13a96926df193912"
    cluster         = "k26d4.13a96926df193912"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "midie ardamax keylogger"
    md5_hashes      = "['6ba8d63c2718c974afee0af117df1864e63f8949','8d90c52484ee446b27a6c002b62adbe0a4976096','d1d30258392750860d12d33ce2bef7f83cb83a27']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d4.13a96926df193912"

  strings:
    $hex_string = { be 4f e6 40 bb eb 0b 85 f3 75 07 8b c6 c1 e0 10 0b f0 89 35 20 d3 00 01 f7 d6 89 35 24 d3 00 01 5e 5f 5b c9 c3 8b ff 55 8b ec 8b 45 08 33 c9 3b 04 cd 88 d0 00 01 74 13 41 83 f9 2d 72 f1 8d 48 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}