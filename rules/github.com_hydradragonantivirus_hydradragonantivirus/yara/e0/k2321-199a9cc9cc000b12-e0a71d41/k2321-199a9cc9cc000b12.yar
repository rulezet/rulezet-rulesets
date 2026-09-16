rule k2321_199a9cc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.199a9cc9cc000b12"
    cluster      = "k2321.199a9cc9cc000b12"
    cluster_size = "15"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos qqhelper"
    md5_hashes   = "['14c251ccd82e6935ab8627e11777a3af','22a55e330894dc2ed10191787fe720cf','fea93635497e1e369d49efa666f664ee']"

  strings:
    $hex_string = { 8e 5a 78 5b 24 76 1e eb 68 d3 3d 2c 74 1b 1c 1f a1 82 31 22 0e ea 4c 6e 61 cc df 73 f8 4d 79 86 c1 16 bf 5e b6 e5 46 30 e0 9e 66 fc 2e 67 92 0d f9 2a e1 8b 60 43 ee 2f 23 bc bb de 28 1b f4 07 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}