rule k2319_1b1596a9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1b1596a9c8800b12"
    cluster         = "k2319.1b1596a9c8800b12"
    cluster_size    = "25"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['d9997d7a0052f233d19337419701aaea3c468667','0d4abb3ba425c9b35552f0c51b8fbca2bd114d28','3f96969e34f93d709ac639561220411324450132']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1b1596a9c8800b12"

  strings:
    $hex_string = "]!==undefined){return G[S];}var p=((0x5B,26)<=50.7E1?(4.39E2,0xc"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}