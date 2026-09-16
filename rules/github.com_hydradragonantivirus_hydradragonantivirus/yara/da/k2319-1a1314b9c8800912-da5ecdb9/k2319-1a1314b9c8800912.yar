rule k2319_1a1314b9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a1314b9c8800912"
    cluster         = "k2319.1a1314b9c8800912"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['b49ad21d0231b8a02d017d3085e32c0b2aea028b','25285ecef0df980151981de39cdeb095cdd46fd5','9212dc46e9652566793920b1c6ad412640b2360e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a1314b9c8800912"

  strings:
    $hex_string = "?(63,119):(23.,0x20E)))break};var a9B9g={'y0m':\"D\",'B2g':functio"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}