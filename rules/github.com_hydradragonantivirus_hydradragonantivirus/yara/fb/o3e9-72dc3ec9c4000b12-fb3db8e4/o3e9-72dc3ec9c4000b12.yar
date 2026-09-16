rule o3e9_72dc3ec9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.72dc3ec9c4000b12"
    cluster      = "o3e9.72dc3ec9c4000b12"
    cluster_size = "60"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock kazy nabucur"
    md5_hashes   = "['0063e61c25f2e2a6fee78e0aaa9a558c','1808ada8ea5a37d888853425cc019485','a3bd9a7a4cf4e1bc9d520d1397acb26c']"

  strings:
    $hex_string = { fd 00 f3 f9 f5 00 cb e1 d3 00 94 c8 95 00 76 ad 62 00 81 a2 73 00 4b b6 73 00 82 a4 7d 00 55 41 3e 00 1a 14 12 00 59 66 4f 00 54 b9 74 00 13 b5 65 00 1b bd 6c 00 15 bd 70 00 43 c4 83 00 df d8 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}