rule o26bb_6b563299c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.6b563299c2200b12"
    cluster         = "o26bb.6b563299c2200b12"
    cluster_size    = "509"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious banker attribute"
    md5_hashes      = "['73189ffb59551f34033831eaaccd11ead3784375','47bdbcdb9356b504c2ca6655d398d6edbcfafc7e','ba59f456dab6dbaf1ae8e1a5f98b0d7ed58c69f4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.6b563299c2200b12"

  strings:
    $hex_string = { fa ef 85 16 fd ff 4d c1 1b df 92 e7 f8 ac d0 5c a3 a0 36 76 4a 83 bb 03 ae da 58 44 a7 b7 25 71 c0 5e 13 ce 2d 0b 00 47 88 50 fe 48 37 89 b0 51 e0 87 b1 2c 24 ab 35 b4 fb 2e 21 15 18 f7 f9 d3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}