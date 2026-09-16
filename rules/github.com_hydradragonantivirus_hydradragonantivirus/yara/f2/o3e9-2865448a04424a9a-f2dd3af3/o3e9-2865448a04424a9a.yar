rule o3e9_2865448a04424a9a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2865448a04424a9a"
    cluster      = "o3e9.2865448a04424a9a"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['0f9f7f98f087994a78431d39826fb899','151c0a6716ed8b976d8d92a546c53bc2','ab61250d47f7bb58946bbf81e121d6ce']"

  strings:
    $hex_string = { 0c 5a a0 cb fa 03 21 75 a7 77 f8 c5 f4 67 66 f7 48 86 5c c9 3d e6 08 93 cd f6 4c de 0e 33 a3 32 38 31 9b 53 90 a9 dc ed a1 a5 2e 02 6a fb 1b d6 91 2f 18 d9 ec cc c1 54 82 07 f3 b6 8e fd ac 10 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}