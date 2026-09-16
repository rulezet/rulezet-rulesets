rule j2321_34c6a5629935d595 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.34c6a5629935d595"
    cluster      = "j2321.34c6a5629935d595"
    cluster_size = "12"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd androm backdoor"
    md5_hashes   = "['1be634aca1e7cc6c8e3bccf2295e2b3a','24d0f958b5cb7d6f7391f55826b165c4','d6b6181fb7b935d39fb48ffdd27c77e5']"

  strings:
    $hex_string = { e8 19 3d ee 94 8a 4e c4 d2 e9 4b 3a a6 2f 9d bf f1 17 0f 03 d1 e0 bb e5 e5 77 95 af 05 7a fc ad 7c f6 dd c1 5f 7d 35 f8 25 9f 67 5f 74 d0 a1 c8 de 4a b9 b0 e7 47 37 dc 0c e3 06 f9 6d 73 72 fe }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}