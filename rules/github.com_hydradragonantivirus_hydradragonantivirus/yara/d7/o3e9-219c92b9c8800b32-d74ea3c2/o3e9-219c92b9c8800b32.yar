rule o3e9_219c92b9c8800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.219c92b9c8800b32"
    cluster      = "o3e9.219c92b9c8800b32"
    cluster_size = "19"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "miniduke backdoor cosmicduke"
    md5_hashes   = "['20da85a976ac80640301e8ecce5e7a7b','226c90b4008285213a928ae9f663548a','d76a3ef9bbc1194a3420ccf8c12769b8']"

  strings:
    $hex_string = { f9 85 1e f0 7a 6a 2b b5 f2 bc f1 cc 5e 0d cb ef d9 a5 12 6b d7 3f 0c 47 48 c9 77 81 ba 45 b4 0f bf 3e d5 1c 98 51 5a 0a 20 fc 51 e0 86 fe 3a b1 76 55 a3 a9 10 b6 1f 2d 05 dc bb e6 26 58 1b ea }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}