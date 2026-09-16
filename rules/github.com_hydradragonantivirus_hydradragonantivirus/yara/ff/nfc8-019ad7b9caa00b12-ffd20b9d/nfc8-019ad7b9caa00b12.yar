rule nfc8_019ad7b9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.019ad7b9caa00b12"
    cluster         = "nfc8.019ad7b9caa00b12"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos banker smforw"
    md5_hashes      = "['0d6cecbbd706e3ad64bc08440126698b879f8a92','308079f3b90e1c4e50245d2e75742c893abe0e92','5060ae8ff7b137304f2a8320062db5558cfec2b4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.019ad7b9caa00b12"

  strings:
    $hex_string = { d9 d1 ea 83 dc 6e d8 29 ec fd d6 22 e6 66 4e cd 2a 6c 94 bc 21 6c 56 db e7 a9 b8 60 ab 1b b3 31 7e a6 8d 8e e9 88 f1 e4 90 1f 52 25 ef 59 b6 04 a3 d2 2f b0 9d fc a2 ce 98 a5 75 54 11 96 13 4b }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}