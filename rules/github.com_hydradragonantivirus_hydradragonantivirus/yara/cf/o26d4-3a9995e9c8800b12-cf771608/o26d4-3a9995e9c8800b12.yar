rule o26d4_3a9995e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.3a9995e9c8800b12"
    cluster         = "o26d4.3a9995e9c8800b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious neoreklami"
    md5_hashes      = "['9ee4f000bf12c56b93549e1a92f4a218d24bd29f','d31e9fb307b0b7c8855fa2ba8f5337f1a9a4926e','8a5594d40efd384abc5f1affaf65e6e3b69c14ab']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.3a9995e9c8800b12"

  strings:
    $hex_string = { 00 33 c9 53 8b 5d 0c 2b d8 43 d1 eb 3b 45 0c 56 8b 75 10 0f 47 d9 85 db 74 23 8b f8 0f b7 07 50 ff d2 8b 55 f4 8d 7f 02 66 89 06 83 c6 02 8b 45 fc 40 89 45 fc 59 3b c3 75 e2 8b 7d f0 89 37 5e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}