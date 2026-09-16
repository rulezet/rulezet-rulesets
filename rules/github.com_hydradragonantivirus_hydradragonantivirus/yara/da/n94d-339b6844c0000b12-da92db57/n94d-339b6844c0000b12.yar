rule n94d_339b6844c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n94d.339b6844c0000b12"
    cluster         = "n94d.339b6844c0000b12"
    cluster_size    = "18888"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "pluma winhlp hlpscript"
    md5_hashes      = "['f5cc1370a0381188a969e0c62defa242488c57b3','b32628138f4c6ccac385231817daee6c96850c16','94d7b613c514ce8758cd2dc8edf796d539c7403f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n94d.339b6844c0000b12"

  strings:
    $hex_string = { 20 5c 81 91 ab fe 83 2f f4 3a f1 04 1f ac 14 51 e3 f3 a1 ef 09 cf 44 c0 d0 02 f8 13 8b 2e c3 06 30 15 1a 6d fa d7 58 25 f0 1e 60 70 90 5a b6 69 41 c4 41 30 9b a1 d4 00 07 63 43 42 4d 5f 43 52 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}