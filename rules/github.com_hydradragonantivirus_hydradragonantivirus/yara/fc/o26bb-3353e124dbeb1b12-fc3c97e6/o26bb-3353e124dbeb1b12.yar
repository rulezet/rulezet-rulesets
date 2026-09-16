rule o26bb_3353e124dbeb1b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.3353e124dbeb1b12"
    cluster         = "o26bb.3353e124dbeb1b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious webalta toolbar"
    md5_hashes      = "['b8ef5a12c5de03fb02fef8a94d3d06a3b28986c2','17b6d7ce46ff630421d27667db36768017928104','a327df6396725ea0671d9c331aebd4b106f69519']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.3353e124dbeb1b12"

  strings:
    $hex_string = { e4 5d bf 7c 29 ed f6 8e ef 99 7d f2 c1 23 63 9e 3e 3a 3d b9 de 6a 44 a9 19 40 df 03 fb e8 f4 dc 60 6e 7a 1b 6b 83 ca f3 c5 d5 b4 7e f0 d8 51 cf 53 4b eb 9b b1 b5 4e a4 ec 07 7b a7 67 4d 94 ad }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}