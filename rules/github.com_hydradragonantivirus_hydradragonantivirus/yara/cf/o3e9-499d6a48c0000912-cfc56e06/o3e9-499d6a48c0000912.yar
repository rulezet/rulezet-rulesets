rule o3e9_499d6a48c0000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.499d6a48c0000912"
    cluster      = "o3e9.499d6a48c0000912"
    cluster_size = "11"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur gena"
    md5_hashes   = "['a046bfe2e54c0e6b6a82b10844036d06','ae78bc56ba749c80716b3f1b21b7971e','dbc85a9e06033e778be73ddea0188af8']"

  strings:
    $hex_string = { 00 29 29 29 03 c3 c8 cc 7b a4 6d 58 ff c3 3c 04 ff c4 59 1e ff ca 64 26 ff d0 6a 25 ff d3 72 30 ff e2 9d 73 ff f1 c6 ae ff ec df d6 ff c9 ee f6 ff 9f e5 f5 ff 5f ce ea ff 39 c3 e5 ff 56 cd e7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}