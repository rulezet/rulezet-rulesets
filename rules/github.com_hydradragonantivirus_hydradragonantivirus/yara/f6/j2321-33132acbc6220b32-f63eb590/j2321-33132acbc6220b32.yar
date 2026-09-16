rule j2321_33132acbc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.33132acbc6220b32"
    cluster      = "j2321.33132acbc6220b32"
    cluster_size = "12"
    filetype     = "MS-DOS executable"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bdmj genpack flooder"
    md5_hashes   = "['02713fdea52f5ab35d131401c85c4376','1ee6b358d9c533291219cc1ddac44c58','f33d52ab6e060e3d686e56de57f91e6f']"

  strings:
    $hex_string = { 9f e8 77 4a 54 70 af 2c 4f e2 e3 27 f0 f1 db 4a ce 31 e5 b2 33 97 a9 8a f3 a1 b8 50 39 16 be 56 c2 fb ca 64 15 e9 c9 5d 32 bb 28 6e 46 61 71 4e 76 21 a4 24 4b 93 82 a0 da 65 59 59 49 69 7e 91 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}