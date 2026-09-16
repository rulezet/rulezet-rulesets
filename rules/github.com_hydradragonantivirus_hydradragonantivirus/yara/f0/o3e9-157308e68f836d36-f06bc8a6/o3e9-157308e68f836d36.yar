rule o3e9_157308e68f836d36 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.157308e68f836d36"
    cluster      = "o3e9.157308e68f836d36"
    cluster_size = "742"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0009c4d5e0ba763bfc5dc1692122ca11','009067301c02225acf79544627a31d65','05d8c27f3d0650d63a1439eac199db75']"

  strings:
    $hex_string = { 4d 32 c9 94 e4 83 c2 df 3a c8 e6 64 c9 ea dc 2f a7 df f0 95 e9 48 0c 01 60 57 4a 6b ac 63 02 97 ef e0 fb 5f 69 22 b0 5c 65 78 62 11 df d9 0b a1 61 12 97 bf fd 5f 2b 80 cf b3 c2 58 e4 14 34 41 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}