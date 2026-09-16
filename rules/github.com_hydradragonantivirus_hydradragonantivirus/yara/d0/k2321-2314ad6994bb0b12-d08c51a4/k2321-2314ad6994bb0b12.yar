rule k2321_2314ad6994bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2314ad6994bb0b12"
    cluster      = "k2321.2314ad6994bb0b12"
    cluster_size = "17"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy emotet tinba"
    md5_hashes   = "['16707e029d7c00566d12d3fec12cb674','247cd004c686763cbb654f132ede2642','fb1186bf12b541f193b4c75646e0cc00']"

  strings:
    $hex_string = { 1e c9 cd 8d e4 ce 88 64 e7 86 b3 26 87 b0 52 03 d9 49 5a 6e b8 46 ac d7 2a 95 72 99 80 bc bd ee cb f0 6b ef f3 7d 26 83 c3 66 89 84 02 b5 42 11 a0 51 07 aa 15 7a a5 34 48 2d 0e 57 8b a2 d4 c2 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}