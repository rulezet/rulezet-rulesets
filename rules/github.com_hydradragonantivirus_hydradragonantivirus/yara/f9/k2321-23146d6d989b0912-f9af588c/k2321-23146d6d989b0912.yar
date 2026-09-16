rule k2321_23146d6d989b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.23146d6d989b0912"
    cluster      = "k2321.23146d6d989b0912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "emotet tinba vbkrypt"
    md5_hashes   = "['50b8fa9489a158f52da500269cd8bf79','7e9aa213222740cdc522c61e75e60d96','abec85cc9b8de9c994edf4f78591bee9']"

  strings:
    $hex_string = { 72 9d 4c a6 95 cb 74 32 b9 3f 6a 36 64 60 89 44 c2 e5 88 39 6c 5c 8c 8d 08 9f 32 61 dc b6 cd 9b 8e 1c 3a 68 69 ac bf 73 f3 c6 d3 87 0f 1e dd bb 7d ff e6 f5 47 77 ef c0 9a 7b b7 6f 99 eb ea 0e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}