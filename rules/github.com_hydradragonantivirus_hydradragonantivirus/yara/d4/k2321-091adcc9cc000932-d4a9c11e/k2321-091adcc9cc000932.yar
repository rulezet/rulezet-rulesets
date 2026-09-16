rule k2321_091adcc9cc000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.091adcc9cc000932"
    cluster      = "k2321.091adcc9cc000932"
    cluster_size = "17"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['0012aee5f1f332f7a5ffa2a7d4bbb7e5','148320d32b3fc3ca2b8c0aa2ff041da5','f79f523b3de712a2e6ed7343bf4a90dd']"

  strings:
    $hex_string = { 1f bf 4b 76 9d b6 1c e8 3c db 09 98 17 e0 9c 37 92 69 39 dc d2 d7 32 02 a4 c0 91 59 57 e9 d9 36 ca 5a 85 99 be 10 66 1a fd 5a f4 d5 84 61 1b 0f 37 6c e3 a1 ac d4 52 25 f2 a2 5d 03 05 c2 9e 19 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}