rule j2318_2694c5a1c2000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2318.2694c5a1c2000b32"
    cluster         = "j2318.2694c5a1c2000b32"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "redirector eiframeinjectadswarenme html"
    md5_hashes      = "['1bb11595a431e874baaf671f92ce5582d6afcea9','32addd1999c607cfb9955567860e34b0c9c58ce3','9a2f0d64caafa13f5dfd482d88a449f49f27aab0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2318.2694c5a1c2000b32"

  strings:
    $hex_string = "ZQo3joMIszqVy-nPit5-vmP1YPAMnbr7eVmA\" />\r\n<!--<meta charset=\"UTF"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}