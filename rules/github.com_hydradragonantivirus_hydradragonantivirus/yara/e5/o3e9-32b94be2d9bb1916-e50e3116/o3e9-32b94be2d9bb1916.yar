rule o3e9_32b94be2d9bb1916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.32b94be2d9bb1916"
    cluster      = "o3e9.32b94be2d9bb1916"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmu mikey fakeav"
    md5_hashes   = "['b2b054d853121534fea76e842e7703aa','c0e1b51adce25c2707e8411b9f2cc715','e486c0ef4faed2e7fb0b5163929f7720']"

  strings:
    $hex_string = { b8 f5 48 0b 62 42 64 4c 4e a0 dd dc cd 65 a9 8c 19 7c 9c d1 93 f9 c1 6b 08 0f 96 6d 09 7d a4 e9 c8 c5 86 4d 6e 3a 60 4f 5c 54 e5 61 ee 2e 7f cb b7 3d e8 81 69 92 c9 30 0d 03 4a 41 ea 63 32 52 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}