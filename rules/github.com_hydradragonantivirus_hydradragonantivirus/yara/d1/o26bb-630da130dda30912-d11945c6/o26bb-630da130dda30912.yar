rule o26bb_630da130dda30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.630da130dda30912"
    cluster         = "o26bb.630da130dda30912"
    cluster_size    = "398"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bundler malicious aeahd"
    md5_hashes      = "['7e032681c2f2a7c4750440c599a6cac38209663b','ed830df8b1d5aa310bf75f83368d75c12ea740a5','518a57636b92470c1737cf95a3b72e9f8d447afb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.630da130dda30912"

  strings:
    $hex_string = { 68 7d fe 7f 00 89 56 18 e8 0b 25 fd ff 8b 55 08 83 c4 5c 8b 5e 18 80 3a 00 75 04 33 c9 eb 13 8b ca 57 8d 79 01 0f 1f 00 8a 01 41 84 c0 75 f9 2b cf 5f 51 52 8d 4b 08 e8 6c 50 fe ff 68 29 0e 65 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}