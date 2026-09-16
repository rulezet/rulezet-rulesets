rule j3f4_090ee53cc2200b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.090ee53cc2200b32"
    cluster      = "j3f4.090ee53cc2200b32"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy malicious agbf"
    md5_hashes   = "['154a2c482c2f877d55747bb918a97099','1cb1d5145b8059857293b990da9168b2','ff71612358d4926787259007ee176ede']"

  strings:
    $hex_string = { 00 00 8f e6 f6 b6 8d e7 f5 fc 8d e4 f4 ff 89 e0 f2 ff 88 de f1 ff 89 dd f1 ff 86 db ef ff 83 d9 ee ff 80 d7 ec ff 7d d5 ea ff 7a d3 e8 de 77 d1 e7 75 00 00 00 00 00 00 00 00 00 00 00 00 c0 7f }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}