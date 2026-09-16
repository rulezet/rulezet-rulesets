rule k2321_0b13a80986220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b13a80986220b12"
    cluster      = "k2321.0b13a80986220b12"
    cluster_size = "37"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['03913b0342d04e1a7be95760e99dfe36','0f526ae2d8efd9f402ee4df990167ef6','5a18a009d6eda0564738669c3fdabd42']"

  strings:
    $hex_string = { 1f 5d 4c fb 93 2f 49 d7 e6 07 e9 e2 77 62 39 d0 94 c3 19 ba ca 27 76 a1 e4 13 1a 32 70 2b 52 29 82 75 f9 42 9f 0b d9 7a 56 7b 24 a0 3d 91 df 12 25 46 bf ef 05 49 c9 6f 3e c2 f6 bc cd 30 5c 5f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}