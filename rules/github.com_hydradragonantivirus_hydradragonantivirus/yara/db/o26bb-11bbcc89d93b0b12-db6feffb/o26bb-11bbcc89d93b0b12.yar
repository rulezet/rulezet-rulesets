rule o26bb_11bbcc89d93b0b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.11bbcc89d93b0b12"
    cluster         = "o26bb.11bbcc89d93b0b12"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy adload genx"
    md5_hashes      = "['b51db59dee8ef594c066902f903eff83f2ba2748','5f6a1b58ff28902e16bd3f407f0145e9497564cf','df84366fa4d58de6ff48b44d4f260dc1e0e79df8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.11bbcc89d93b0b12"

  strings:
    $hex_string = { 4f 44 45 4c 41 59 3a 20 25 73 0a 00 00 54 43 50 5f 4e 4f 44 45 4c 41 59 20 73 65 74 0a 00 00 00 00 73 61 5f 61 64 64 72 20 69 6e 65 74 5f 6e 74 6f 70 28 29 20 66 61 69 6c 65 64 20 77 69 74 68 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}