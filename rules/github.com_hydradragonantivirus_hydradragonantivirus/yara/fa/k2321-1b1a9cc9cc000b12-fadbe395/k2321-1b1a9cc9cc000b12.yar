rule k2321_1b1a9cc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1b1a9cc9cc000b12"
    cluster      = "k2321.1b1a9cc9cc000b12"
    cluster_size = "10"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['044b216f0fb863f53815d2e0dab24894','0bb4beb8f8c64b280de0036445ba5ef5','e156f7b2b2500442518a6e8a58dff4cc']"

  strings:
    $hex_string = { ae 1a ef 61 94 e4 a5 b7 9c 55 6a 33 3b f8 2d 9a 99 df 53 d9 0f 66 e6 a9 0a 2c 97 c7 2e 22 0e 74 f0 5f 2f b4 e9 15 3f 71 0b 20 96 be ba aa 4c 12 f8 ac 4f 03 a6 ed 16 25 4e c8 b3 28 3e 27 cd a2 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}