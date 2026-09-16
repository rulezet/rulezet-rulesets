rule k3e7_11b5b49cc2230b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.11b5b49cc2230b16"
    cluster      = "k3e7.11b5b49cc2230b16"
    cluster_size = "53"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dinwod kazy trojandropper"
    md5_hashes   = "['4cacb82ba1e1230ddc4de13cd416ba1c','bca17e00dd1cdcab53f291548cff0eef','bca17e00dd1cdcab53f291548cff0eef']"

  strings:
    $hex_string = { e4 19 6b 43 47 20 e7 80 8d d2 1a 1b 44 fd 0e 9b 17 c7 da 42 58 13 f7 61 9e 04 76 38 a2 95 ea 62 6c 6f 1e 6a 01 e3 fe 2d df f0 c4 22 e8 85 7d d3 a5 08 7e e8 02 00 3f f4 db 1d fb 9c 10 2a 3e 39 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}