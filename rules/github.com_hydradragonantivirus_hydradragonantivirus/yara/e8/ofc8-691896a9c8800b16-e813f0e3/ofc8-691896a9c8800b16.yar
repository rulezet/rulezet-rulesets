rule ofc8_691896a9c8800b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.691896a9c8800b16"
    cluster         = "ofc8.691896a9c8800b16"
    cluster_size    = "198"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['448fada2536b5f39e1337950279d53a0375bda28','c06c12f1d9f2c69199c32d3d4ece1c436b9ed088','301d29da8f37131d22914739e92fa0c7a3570077']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.691896a9c8800b16"

  strings:
    $hex_string = { b2 7c be bc ef 29 56 62 9f 8c cc fe d2 38 e3 5b d8 82 3c 3e 01 8f ab 68 a4 52 11 4f ce 8a b5 95 8d 4e f4 9d 23 06 72 91 ad d4 41 d7 ee 6a c0 3b 43 a2 b1 84 36 a0 c8 0f 45 60 f3 37 cb 16 ae 93 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}