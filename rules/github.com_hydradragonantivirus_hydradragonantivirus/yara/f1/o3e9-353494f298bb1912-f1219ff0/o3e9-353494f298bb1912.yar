rule o3e9_353494f298bb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.353494f298bb1912"
    cluster      = "o3e9.353494f298bb1912"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmu mikey malicious"
    md5_hashes   = "['041d3783611ed91d9edbed5141365802','0f5f602711edfb38fc6cb39878c14eec','e23a2e9ee194089c76e78a390ea88de5']"

  strings:
    $hex_string = { 07 19 ae 27 f3 84 00 57 71 e7 1e 68 74 c8 32 47 c4 8a 98 85 9d 7d a8 78 f8 31 35 f7 45 55 81 5c 3d 96 a4 43 cf ca d5 f5 c9 bd f9 93 86 75 ef ea 44 e9 4e 50 49 fa a9 0a 0b 34 05 1f 77 36 87 ad }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}