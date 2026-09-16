rule j26c9_3dad0cc0c4001112 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26c9.3dad0cc0c4001112"
    cluster         = "j26c9.3dad0cc0c4001112"
    cluster_size    = "1110"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mikey tempedreve filerepmalware"
    md5_hashes      = "['a1c91e8b076f42db71ab961755887c7d1dfeb6bd','ac2189c430f0603c07e0aef54e261aac7a627494','91b5b146a0a7b105b2f3aaeafc25f0d61b5af965']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26c9.3dad0cc0c4001112"

  strings:
    $hex_string = { 8b 45 e8 44 0f b6 10 48 03 c6 41 8b ca 48 89 45 e0 23 ce 83 c1 02 41 d1 ea 74 21 85 c9 0f 84 0c 01 00 00 41 8b d2 48 f7 da 42 8a 04 02 41 88 00 4c 03 c6 ff c9 75 f2 e9 ef 00 00 00 8b fe e9 ec }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}