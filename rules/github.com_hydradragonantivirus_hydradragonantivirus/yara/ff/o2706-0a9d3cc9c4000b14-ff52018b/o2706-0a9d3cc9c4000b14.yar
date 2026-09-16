rule o2706_0a9d3cc9c4000b14 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2706.0a9d3cc9c4000b14"
    cluster         = "o2706.0a9d3cc9c4000b14"
    cluster_size    = "101"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "browsefox ursu injector"
    md5_hashes      = "['de05b423ba3c5efa5a7661823d2ff4124129fa1a','0658b6653b50a1304bcae10cd18c212803ca80ed','dc91927392101053be7aa7ded5dd1f2134c32398']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2706.0a9d3cc9c4000b14"

  strings:
    $hex_string = { d2 ad 01 00 7a 3c ac 09 65 c7 01 00 4a a6 2c 09 f1 56 00 00 5e 3c e1 08 3e ac 01 00 f4 7b 89 09 5f de 01 00 9b 33 91 01 fc cb 00 00 99 01 49 04 64 a1 01 00 4e a7 1c 05 0b 93 02 00 13 a6 0c 05 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}