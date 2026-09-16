rule k2321_0a40a856166b48ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0a40a856166b48ba"
    cluster      = "k2321.0a40a856166b48ba"
    cluster_size = "17"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['1844ea9da14b76afb4abb19eccac3b3d','26cf4858e572fbb7b179e63d86d6786e','eaf10c6d2167750a83bd4577fbeb0da0']"

  strings:
    $hex_string = { 14 7f f0 46 6f bf ab 35 c0 9c d8 9f c7 05 24 68 00 12 64 66 a4 0d e5 62 6e 89 b4 a3 5c 21 d6 b0 79 fa d1 d3 ef d2 c5 77 8c 5f a2 45 c3 8d 73 40 94 82 7a 42 d5 43 59 7c 75 3c 3b c6 60 0b 70 74 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}