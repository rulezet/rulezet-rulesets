rule k2321_29146d6d94bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29146d6d94bb0b12"
    cluster      = "k2321.29146d6d94bb0b12"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy emotet"
    md5_hashes   = "['07d8187dcd4a9599730616dc59339602','3dcde55d9eb7c89671c41a7e05b68224','90eb249e384184d8a2e85a2917c5f4a9']"

  strings:
    $hex_string = { 37 92 9d 13 ce 9a 1c c2 4a 0d 64 27 69 b9 e1 1a b1 5e ab 54 ca 65 02 f2 f6 ba 2f c3 af bd cf f7 99 0c 0e 9b 25 12 0a d4 0a 45 80 46 1d a8 56 e8 95 d2 20 b5 38 5c 2d 8a 52 0b a3 35 82 68 8d 30 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}