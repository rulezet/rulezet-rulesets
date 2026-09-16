rule o3e9_43b0cad3c4001912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.43b0cad3c4001912"
    cluster      = "o3e9.43b0cad3c4001912"
    cluster_size = "183"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bqjjnb"
    md5_hashes   = "['022efb2b3cdd015423f462467be9c848','03137cd6e11d4e2dd899e29b85fe6d87','2fa9407ab17c95c11777b9d987c85bad']"

  strings:
    $hex_string = { 48 33 c9 a3 fc ca 4c 00 38 08 0f 94 c1 41 51 8d 4d e4 e8 99 de ff ff e9 12 01 00 00 53 57 b9 88 b4 4a 00 6a 12 8b f9 8b f0 5b 8a 16 84 d2 74 09 3a 17 75 05 46 47 4b 75 f1 0f b6 16 0f b6 37 2b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}