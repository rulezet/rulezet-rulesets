rule k3e9_332d36c126a7cb16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.332d36c126a7cb16"
    cluster      = "k3e9.332d36c126a7cb16"
    cluster_size = "223"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "munlight amvu badclean"
    md5_hashes   = "['005cf0a8f5a8489290cd84d2506cea7e','02ea5dcdd543d11d4e853207b9ee1d85','18eb1aef5a052a474f0e26f74d27539f']"

  strings:
    $hex_string = { c9 2e f7 67 66 cc f4 21 20 8a 7e 94 09 6e 4e 14 62 c5 d8 0d 0e 78 87 86 88 37 f3 e4 77 4d 1e fe 73 36 e5 2b b0 15 b3 26 00 e0 5c 82 19 f8 3a c0 7c 38 39 cf 70 9e e8 81 55 ae bc 10 ff 1c 5f 8f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}