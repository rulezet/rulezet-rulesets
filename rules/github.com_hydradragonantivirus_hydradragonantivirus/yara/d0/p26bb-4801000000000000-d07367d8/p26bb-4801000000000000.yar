rule p26bb_4801000000000000 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.4801000000000000"
    cluster         = "p26bb.4801000000000000"
    cluster_size    = "1022"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious tofsee attribute"
    md5_hashes      = "['fa8007521e3737da168352f1e9c7fd56b14f9223','5333c12330d89b2c26de12b5a4ce91cc4b209a6d','ac6a3cbc1562c76864320264beb266067e27c73a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.4801000000000000"

  strings:
    $hex_string = { d3 4e 98 bc 8f c3 ad 45 ed a0 ff ff f1 46 fc 0f d6 ad d0 47 9b 92 6f c2 91 87 26 22 c9 7f 22 6c 89 1a 12 0b 18 84 cd e5 e2 03 48 7a aa e4 b3 34 02 0b 64 be 2b 54 a1 72 7b b4 38 b7 cb a7 d5 de }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}