rule k2321_0969592399eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0969592399eb1912"
    cluster      = "k2321.0969592399eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['129b6acd43a85718fc4052ade2fb8d4d','4ceff5a2fd12dd8144468a2f29afbae8','cb93e1f0e8742c0729a23519df456a20']"

  strings:
    $hex_string = { 59 e4 f6 14 c3 db 2d 32 de 4a 5a e9 33 7f ae 52 ef ba 83 40 2b e3 07 a6 dd 97 6f f8 a6 3c 8f b0 12 7e 86 9a 23 6b b7 d3 a4 9d e5 d6 ac bf a7 f2 c0 57 5e dc 3b e7 d2 06 82 ed 08 87 0e 8e c1 b4 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}