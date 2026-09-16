rule ofc8_5911a64bc6220b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.5911a64bc6220b32"
    cluster         = "ofc8.5911a64bc6220b32"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['5d9d240cb690d182eb1cac9b2a138aac89d21eec','a9172183b75b2e07b409660a33c58962de455237','dd72b0f0e899c730dba20c45d24c8930c5e9ab2a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.5911a64bc6220b32"

  strings:
    $hex_string = { de e3 b1 b6 39 4d 3f c5 89 17 9f 68 9b 4e 53 ad b5 cf cd b7 23 5c 60 79 41 2d 7b 67 93 96 d5 52 42 62 d7 5e 19 5d bb a0 9d ef 06 bd 0a 78 92 45 b2 e0 3c 10 a3 c8 e5 30 0e db ab 64 a9 d9 a8 48 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}