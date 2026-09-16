rule o3e9_1110c48cda630912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1110c48cda630912"
    cluster      = "o3e9.1110c48cda630912"
    cluster_size = "2773"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "advml backdoor dragon"
    md5_hashes   = "['00298a028f6bdbf37d0beb508cdcaf2a','002af2fdf88ccbb055147993cefd43b4','0185e056dd5204c4a27fff667188c3f8']"

  strings:
    $hex_string = { 66 b7 04 b0 91 c8 36 57 16 23 a1 07 a6 dd 78 18 c6 8e cb e6 f8 9d fd 54 97 38 04 05 55 4f c8 48 ac bf 46 2c 90 1d 96 7b f7 52 31 d3 6a 23 6c 56 a4 d1 7d 45 15 32 7d 3c d7 ba 25 0b 02 bb 6a 41 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}