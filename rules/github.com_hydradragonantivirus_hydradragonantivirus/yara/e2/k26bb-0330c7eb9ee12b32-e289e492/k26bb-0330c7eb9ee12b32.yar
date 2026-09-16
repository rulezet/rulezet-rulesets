rule k26bb_0330c7eb9ee12b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.0330c7eb9ee12b32"
    cluster         = "k26bb.0330c7eb9ee12b32"
    cluster_size    = "47"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "unwanted widgi creprote"
    md5_hashes      = "['025e77b908baff93ab425b6d9d6076d9557ae96b','265260f3437881cee9e4a76478a1cc371311b2e1','ddcd76583895649893bf7627747a30108741ba37']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.0330c7eb9ee12b32"

  strings:
    $hex_string = { ff f0 1b 4a 48 53 8f 75 fa e5 f1 a1 15 01 3e e7 f2 6d a8 a4 0f 21 d6 05 63 b5 0e 3a b4 7a 59 b1 76 e2 aa dd 93 47 f7 02 74 49 11 2d d5 78 6c 18 6e 5e ee f6 a2 43 85 00 23 55 91 0d 56 de 03 58 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}