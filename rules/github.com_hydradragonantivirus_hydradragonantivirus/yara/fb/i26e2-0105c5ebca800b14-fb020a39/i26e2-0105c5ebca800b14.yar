rule i26e2_0105c5ebca800b14 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26e2.0105c5ebca800b14"
    cluster         = "i26e2.0105c5ebca800b14"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dorkbot winlnk autorun"
    md5_hashes      = "['4d72bed00c075394c59304992f987b77b1cfc504','12245943077393a5c8ae9331260672d44bed526e','b288b8a12a90077e75b8402d878e95e912ffa5ac']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26e2.0105c5ebca800b14"

  strings:
    $hex_string = { 1f 50 e0 4f d0 20 ea 3a 69 10 a2 d8 08 00 2b 30 30 9d 19 00 2f 43 3a 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3c 00 31 00 00 00 00 00 00 00 00 00 10 00 77 69 6e 64 6f 77 73 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}