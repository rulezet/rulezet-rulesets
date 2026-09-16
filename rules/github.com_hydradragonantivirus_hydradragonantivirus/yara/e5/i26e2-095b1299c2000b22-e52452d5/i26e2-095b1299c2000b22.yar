rule i26e2_095b1299c2000b22 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26e2.095b1299c2000b22"
    cluster         = "i26e2.095b1299c2000b22"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dorkbot winlnk dobex"
    md5_hashes      = "['f76a1fdaad03bbde87b9fc13f767e5a9805b0a78','ac41df9275a4ddca3a33b1aab55fe48fa29bf5de','af81739b10d10fa3399ff973e8d1a69ee895b9cb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26e2.095b1299c2000b22"

  strings:
    $hex_string = { 2e 00 64 00 6c 00 6c 00 14 03 00 00 01 00 00 a0 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c 2e 2e 5c 2e 2e 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}