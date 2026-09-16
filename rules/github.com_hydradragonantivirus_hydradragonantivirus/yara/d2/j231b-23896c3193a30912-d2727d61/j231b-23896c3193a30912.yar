rule j231b_23896c3193a30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j231b.23896c3193a30912"
    cluster         = "j231b.23896c3193a30912"
    cluster_size    = "17"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "coinminer coinhive miner"
    md5_hashes      = "['2f10a6abeff773f35de8bc5c3942f89c7cea922c','00649caa5fd4b15da7e9c78e1a1ef45ec7977fdb','4e2024894fd4b54a3dc83b4ef9ed58f715e96f20']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j231b.23896c3193a30912"

  strings:
    $hex_string = { 3d 45 6d 75 6c 61 74 65 49 45 37 22 20 2f 3e 0d 0a 0d 0a 3c 74 69 74 6c 65 3e 5a 4f 4e 41 20 43 41 4c 45 54 41 20 50 45 52 c3 9a 20 26 62 75 6c 6c 3b 20 49 64 65 6e 74 69 66 69 63 61 72 73 65 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}