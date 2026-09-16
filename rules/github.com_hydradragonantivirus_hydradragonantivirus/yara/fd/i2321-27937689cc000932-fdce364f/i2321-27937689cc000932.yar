rule i2321_27937689cc000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.27937689cc000932"
    cluster      = "i2321.27937689cc000932"
    cluster_size = "13"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['4470df5a163f27ed6dc493460b1ca340','4914df6008aadf5bdaca8744cd140bec','e4bf3e7635d6e72f4de01c49d1457a21']"

  strings:
    $hex_string = { d8 33 71 76 27 4a 17 d3 c0 d1 e1 e9 38 c1 cd 16 57 e2 8c e3 58 c7 17 2a 73 a5 5a ba 90 d8 62 72 74 64 6c 6b 28 3e 72 6d d9 cf e1 be f8 95 fe e7 78 5b f3 67 df 3d f1 9d f1 f7 e2 68 cc cd c4 c2 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}