rule j3f8_566ae66b2b40c66e {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f8.566ae66b2b40c66e"
    cluster      = "j3f8.566ae66b2b40c66e"
    cluster_size = "13"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jisut ransom androidos"
    md5_hashes   = "['0e9b437d30eb665c7ac8e2fa5f6adedd','12216c79249eb851b77c8c7b2ba19ed0','fef34d337df61979d1319cc7c4a3e2ad']"

  strings:
    $hex_string = { 77 69 64 74 68 00 08 77 6d 50 61 72 61 6d 73 00 01 78 00 01 79 00 05 e8 be 93 e5 85 a5 e5 af 86 e7 a0 81 ef bc 81 00 04 e9 9a 8f e6 9c ba e7 a0 81 3a 00 0c 4c 63 6f 6d 2f 68 2f 52 24 69 64 3b }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}