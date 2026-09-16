rule o26bb_09bb6689de3b1932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.09bb6689de3b1932"
    cluster         = "o26bb.09bb6689de3b1932"
    cluster_size    = "132"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious softcnapp"
    md5_hashes      = "['d2f52dbbe82fcf9b0252ad39224b57b3a931765a','d94ee2d0ebb843560a3767e195256c9ede061bb1','a9dbea6f5d71a1fe69246cea848845684482d1dd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.09bb6689de3b1932"

  strings:
    $hex_string = { 1a 3b 4d d8 77 1d 03 75 cc 2b 55 ec 01 5d ec 8d 0c 1e 89 4d b4 8b d9 8a 0c 32 88 0e 46 3b f3 75 f6 eb 29 8b 45 cc 8b 7d d8 66 0f 1f 44 00 00 8a 0c 02 42 88 0c 06 33 c9 46 3b d7 0f 44 d1 83 eb }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}