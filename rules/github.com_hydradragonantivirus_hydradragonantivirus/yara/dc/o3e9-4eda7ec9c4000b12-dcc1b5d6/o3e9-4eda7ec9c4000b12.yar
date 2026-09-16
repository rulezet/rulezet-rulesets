rule o3e9_4eda7ec9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.4eda7ec9c4000b12"
    cluster      = "o3e9.4eda7ec9c4000b12"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock tdss nabucur"
    md5_hashes   = "['b13b232d325fa4db41d00f9b57d3e675','b2dfcb0ce2672f5cefb3be6f4dc614b0','d9526103a8083c9338646e6731c99a08']"

  strings:
    $hex_string = { dc e8 00 b0 c2 d1 00 56 6f 83 00 85 95 a3 00 65 7d 99 00 b5 c8 e2 00 f2 f8 fc 00 b1 c6 ef 00 b6 c9 eb 00 9f b4 cc 00 d7 e4 f0 00 b3 c5 d6 00 47 5d 66 00 1d 28 23 00 1d 27 21 00 1a 1e 17 00 0c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}