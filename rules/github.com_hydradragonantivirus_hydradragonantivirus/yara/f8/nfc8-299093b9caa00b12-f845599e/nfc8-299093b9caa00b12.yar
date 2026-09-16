rule nfc8_299093b9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.299093b9caa00b12"
    cluster         = "nfc8.299093b9caa00b12"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cryxos androidos banker"
    md5_hashes      = "['7226c00477e28fe1389560ef988d705bb2b13df2','03e1d69e41bec7ddb9e385f95a9752809c9b5121','9d156e2a1646f857fd641be6241bf1c2cf2998e7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.299093b9caa00b12"

  strings:
    $hex_string = { 7d 4b a0 ba 7f 40 e7 23 e8 8b 56 92 94 8f 58 50 3a 5d 80 1c 86 2b f3 13 04 fd bb c4 46 05 97 64 0f 25 7c 29 aa a9 06 72 88 cc af f4 b8 f2 20 a7 0a 6d d1 de ee d9 48 98 5e 34 c8 31 19 a8 27 5f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}