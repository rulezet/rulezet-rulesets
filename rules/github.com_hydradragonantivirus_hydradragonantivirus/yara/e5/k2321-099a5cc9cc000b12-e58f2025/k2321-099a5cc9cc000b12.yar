rule k2321_099a5cc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.099a5cc9cc000b12"
    cluster      = "k2321.099a5cc9cc000b12"
    cluster_size = "22"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['0262c356e63bd93d7d2da3215a43171b','098d5c0533b0390d7d7e2f3f52767eff','ca23070ff8499ccc2a32b0ad44f9a735']"

  strings:
    $hex_string = { 80 0e 50 1a 8f be 85 ab 3c 6d 70 59 da 5e c1 88 01 0c b7 b5 b0 e3 e2 3b 2d 03 9e f6 ec 0b 92 d4 f2 75 6f 0c e2 36 1f ba 23 f1 70 d7 90 ca 22 1e 3e db 26 1d eb b8 00 e4 7b 4e 7c ff fc 9f 97 81 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}