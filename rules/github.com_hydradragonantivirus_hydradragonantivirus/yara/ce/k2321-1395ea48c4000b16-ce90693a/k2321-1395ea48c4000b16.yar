rule k2321_1395ea48c4000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1395ea48c4000b16"
    cluster      = "k2321.1395ea48c4000b16"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd upatre"
    md5_hashes   = "['2c1abb57edca65576e885c5e6dbdf38c','398e8a41938f6a8fcf09218eff84bcdd','770939b201792438a2ae5e8b85dc2402']"

  strings:
    $hex_string = { 30 dd 58 2d 47 b9 37 3c 45 e4 4a cd a7 3d 6d 76 2a 7b da 85 f8 73 9e 1c 22 5e e9 c9 e7 b3 4c 5b a3 34 0d 1f a6 17 d2 b2 08 5a de 40 6c 93 26 b7 df a5 b6 ec cc cb ed 89 3f 57 49 7d 3e 13 12 33 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}