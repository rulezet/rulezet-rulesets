rule o3e9_533c9ac9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.533c9ac9cc000b12"
    cluster      = "o3e9.533c9ac9cc000b12"
    cluster_size = "7"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock ksdmi cryptor"
    md5_hashes   = "['75cfd034f72966d9de76a5f8ddf579b9','a8f807ec735b96b1b133ea444ad92dfc','de9de03c9e0cb97a27565ca60f190891']"

  strings:
    $hex_string = { f9 f5 ff fe f8 f2 ff fe f6 ef ff fe f5 ed ff fe f4 ea ff fc f1 e7 ff e4 b5 90 ff ed a0 47 ff e6 94 38 ff dd 8a 36 ff d4 81 35 ff b4 80 61 ea 4a 30 23 62 4b 37 2a 27 46 46 2a 09 7f 7f 7f 01 00 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}