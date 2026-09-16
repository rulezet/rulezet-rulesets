rule o3e9_6114a48bc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.6114a48bc6220b12"
    cluster      = "o3e9.6114a48bc6220b12"
    cluster_size = "658"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "lethic ayzg cryp"
    md5_hashes   = "['004ad7d499b2a77f44890e78007d89c5','01232c4cda964b2116a880d753f1864a','13db246e303263bc74536906f9efd274']"

  strings:
    $hex_string = { a0 e1 46 39 2a 56 83 0f e6 cd 56 4b e0 c7 94 02 75 13 93 e1 73 73 c7 90 07 31 4c 6d 57 39 fa e1 ab 06 4d 28 2b 85 ff 8b f4 01 4d 53 7b 64 89 07 36 92 b3 b8 31 99 ee fb a5 14 99 da ff 5a 12 82 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}