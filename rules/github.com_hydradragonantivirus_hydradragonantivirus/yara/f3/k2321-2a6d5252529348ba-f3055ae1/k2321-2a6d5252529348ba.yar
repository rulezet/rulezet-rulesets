rule k2321_2a6d5252529348ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2a6d5252529348ba"
    cluster      = "k2321.2a6d5252529348ba"
    cluster_size = "26"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy flmp"
    md5_hashes   = "['0736e43a5a8300832971351ddb11b3f6','12893df677a006c892e3f958de3286c2','8632b29ac0b31a422c1ab679693e93e5']"

  strings:
    $hex_string = { 95 20 39 c7 04 37 0f 66 07 5a c4 4c bb de e8 0b d3 9d 09 94 db 51 78 fe 27 e6 e5 56 53 3d 1f 62 5e 67 16 73 2b 43 c8 b2 70 ad d8 8d f6 13 81 c5 7d 42 92 55 82 ed 21 b0 97 d7 59 a5 0d a3 d9 8f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}