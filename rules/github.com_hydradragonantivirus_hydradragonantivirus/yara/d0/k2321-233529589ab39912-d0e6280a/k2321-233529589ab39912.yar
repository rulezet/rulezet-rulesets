rule k2321_233529589ab39912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.233529589ab39912"
    cluster      = "k2321.233529589ab39912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dinwod malob trojandropper"
    md5_hashes   = "['0ec5602cc2daa3da3a2ae33dc92d937b','b8e93c16e5c5247e6c4afe8084e23872','d8fd6465cc94503c705c6d6bba1365fd']"

  strings:
    $hex_string = { e7 60 ac 70 1b b8 08 e4 8b 44 c6 97 74 52 b4 28 c6 c3 ee e5 e8 0e f7 7f 5b 2a df 7a 6b d6 7d bb 77 1d 1a b0 bd 25 b9 d3 5e 2f 8c 4a a5 99 90 a7 5f 6f fe f5 71 9d d2 59 7b 85 f6 6c ba 87 02 6d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}