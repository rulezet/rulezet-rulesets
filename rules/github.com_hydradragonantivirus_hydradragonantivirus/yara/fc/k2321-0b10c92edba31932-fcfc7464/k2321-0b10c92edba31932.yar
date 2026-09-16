rule k2321_0b10c92edba31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b10c92edba31932"
    cluster      = "k2321.0b10c92edba31932"
    cluster_size = "9"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hupigon backdoor razy"
    md5_hashes   = "['2f2e82e25de183689cce5139e4d90974','52a5be300bb4697c04b6ce62dfd68281','afbebbc6dafae17ec9337bf08ce9e461']"

  strings:
    $hex_string = { 64 52 d7 a4 37 79 84 65 e3 a3 2f 2b 75 3d 09 b2 be 4e 30 59 f9 92 d6 21 b9 ee 12 de 79 ba 9d aa c5 7e 93 07 a1 25 da fc ae 62 f6 55 1b bc 8b 45 05 ff 60 80 aa 39 c1 f5 e0 e5 5e e7 ab 8f 35 f0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}