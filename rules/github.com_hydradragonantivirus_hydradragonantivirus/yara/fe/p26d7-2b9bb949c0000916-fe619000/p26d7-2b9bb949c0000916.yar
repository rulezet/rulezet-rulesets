rule p26d7_2b9bb949c0000916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26d7.2b9bb949c0000916"
    cluster         = "p26d7.2b9bb949c0000916"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "softpulse malicious digitalplu"
    md5_hashes      = "['3f41872b036d667379aa3cc1d4e44827b5a0bb30','1b3fd2f29f8f87ae5f0caea4863caaa577658f3a','1d14d50e578d7fba08ce789180baa68cd28abf09']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26d7.2b9bb949c0000916"

  strings:
    $hex_string = { cc f3 ab 59 a1 60 4f 84 00 33 c5 50 8d 45 f4 64 a3 00 00 00 00 89 4d f0 8b 45 08 83 38 03 74 11 6a 5f 68 e0 27 7c 00 e8 d2 90 fa ff 85 c0 74 01 cc 8b 55 08 0f b7 42 0c 89 45 ec 83 7d ec ff 75 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}