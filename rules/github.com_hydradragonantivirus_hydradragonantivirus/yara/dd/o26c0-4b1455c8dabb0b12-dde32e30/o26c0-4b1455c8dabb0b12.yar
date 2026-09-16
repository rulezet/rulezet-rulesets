rule o26c0_4b1455c8dabb0b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.4b1455c8dabb0b12"
    cluster         = "o26c0.4b1455c8dabb0b12"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor malicious gjjv"
    md5_hashes      = "['7d20ca94ae516b90a838ddf48c60f7a26ef9e746','dfddf3c5bf5f901a9edad4fa5a44c79ebe62f2d5','3818eacdcab5b498b46bd66ab6d00a244c6924e9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.4b1455c8dabb0b12"

  strings:
    $hex_string = { 1c 06 20 d3 e7 04 fd 86 53 ff 34 98 46 72 35 4a 14 b3 75 9d e8 85 9c 05 d0 50 2b ba 5d 00 f3 8e b2 6c 41 e9 77 61 08 83 84 ce f4 eb bd a5 a2 e6 69 53 9f 3a 3f 40 37 00 ac 0e 45 ea 81 92 f9 7e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}