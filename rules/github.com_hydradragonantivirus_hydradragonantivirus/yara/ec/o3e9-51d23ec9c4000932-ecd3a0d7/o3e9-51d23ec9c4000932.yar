rule o3e9_51d23ec9c4000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.51d23ec9c4000932"
    cluster      = "o3e9.51d23ec9c4000932"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock krypt nabucur"
    md5_hashes   = "['5fe8659337514506e1bb44b71d3b9376','77d41fc79de608c167cb1b33adc7e866','cd694608f771b8e72ba834d47c8ff5ac']"

  strings:
    $hex_string = { 00 42 a5 f8 00 46 b0 da 00 25 64 b7 00 c3 b5 a6 00 2b 78 bf 00 1c 75 ce 00 55 b4 c1 00 ae 60 f5 00 c6 c3 dd 00 88 b1 ee 00 58 8c d8 00 26 6d ff 00 87 a4 c2 00 21 80 d5 00 6f a8 ea 00 65 91 ef }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}