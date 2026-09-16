rule o3e9_0ab16322b43848b3 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0ab16322b43848b3"
    cluster      = "o3e9.0ab16322b43848b3"
    cluster_size = "13"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster bundler malicious"
    md5_hashes   = "['13b0191cbd0ccded83edf7c0ba9ea2c0','143df96822f737130f040f23f0384d1e','fba99ff11127e0f390ca45af5518bc20']"

  strings:
    $hex_string = { 5a 0e 17 ca dd ab 42 4e c5 34 bd 86 3f 58 48 50 9e ad 89 68 3a 8f cd 8b de aa 14 55 81 66 d3 e3 29 b1 6e 39 74 53 6d 13 41 22 c0 08 5f 7f 06 65 bf a4 e5 c8 87 98 f0 f8 8e fe a9 d2 a6 ae 96 11 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}