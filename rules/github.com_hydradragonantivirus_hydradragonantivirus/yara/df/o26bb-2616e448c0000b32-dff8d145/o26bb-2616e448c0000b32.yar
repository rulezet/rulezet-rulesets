rule o26bb_2616e448c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.2616e448c0000b32"
    cluster         = "o26bb.2616e448c0000b32"
    cluster_size    = "17"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "ursu malicious patched"
    md5_hashes      = "['5e245718d3453e82739a0d475685ea68eccb0f05','25c5fd5683d112aabbe96d8253c2883095916d6d','f11a29551157103e55c4c356be54166fb4dcda30']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.2616e448c0000b32"

  strings:
    $hex_string = { 5c 24 08 8a 1b 4a 88 19 41 85 d2 77 f2 03 c7 89 46 10 5b c2 04 00 b8 5f 1c 45 00 e8 cb 81 03 00 83 ec 24 53 56 8b d9 8b 73 0c 57 89 65 f0 85 f6 75 04 33 ff eb 0d 8b 43 14 2b c6 6a 1c 99 59 f7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}