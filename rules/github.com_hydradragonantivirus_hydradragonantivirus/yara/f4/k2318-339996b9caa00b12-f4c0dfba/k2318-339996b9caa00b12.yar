rule k2318_339996b9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2318.339996b9caa00b12"
    cluster         = "k2318.339996b9caa00b12"
    cluster_size    = "22"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "iframe html redir"
    md5_hashes      = "['23ecce0dfbd5cd5dfc8ba98ae6a887f8d2476d84','2c34f9041f7e98afbcb0f2e5cbec8bb7a27b8470','857c9f39615c2c063ad6d6c2d914ced096bed558']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2318.339996b9caa00b12"

  strings:
    $hex_string = { 64 20 77 69 64 74 68 3d 22 31 30 30 25 22 20 68 65 69 67 68 74 3d 22 31 34 22 20 63 6c 61 73 73 3d 22 69 6e 66 6f 42 6f 78 48 65 61 64 69 6e 67 22 3e d0 e0 e7 e4 e5 eb fb 3c 2f 74 64 3e 0a 20 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}