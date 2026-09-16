rule k2319_291294e9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.291294e9c8800b32"
    cluster         = "k2319.291294e9c8800b32"
    cluster_size    = "41"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['a7562e2d31e7bfed26c650b394f2bea48f94cdcc','6dc2389c0e1a03ace7bb8b2983a1f588c6579b82','59344b96a163657f376245664ae000cb34d98253']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.291294e9c8800b32"

  strings:
    $hex_string = "(0x21B,2.81E2)))break};var s4G={'i54':6,'a64':\"I\",'Q':function(G"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}