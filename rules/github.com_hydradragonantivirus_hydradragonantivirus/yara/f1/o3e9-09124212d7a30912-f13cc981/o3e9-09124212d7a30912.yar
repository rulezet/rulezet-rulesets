rule o3e9_09124212d7a30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.09124212d7a30912"
    cluster      = "o3e9.09124212d7a30912"
    cluster_size = "63"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor noobyprotect fuery"
    md5_hashes   = "['008b486ce67ea345af8de6f648e028f7','038e1b934659ebbea511968e55cc4146','3d787e1deaad59dc3fa99f5aaf7e98c9']"

  strings:
    $hex_string = { 89 83 b7 9b c7 d9 e4 59 8d 9f 57 08 e2 f6 7a 6f 77 13 8b d8 be d7 2d ce 36 91 cd 99 4c 86 46 25 fc 2e a0 e5 60 b2 af 50 93 61 5d 03 97 1e e9 95 df b5 0e b1 11 8e 28 35 e7 ad c0 d3 5b 3a 32 a9 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}