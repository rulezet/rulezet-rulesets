rule o3e9_0b916d2f2c744ad3 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b916d2f2c744ad3"
    cluster      = "o3e9.0b916d2f2c744ad3"
    cluster_size = "285"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dlboost installmonster malicious"
    md5_hashes   = "['0075501dcd9ef295d78798967bc7ed50','02428f05f176c2dde978c6f98c3cc2dd','0e64fe257d9100f002aa5c9b73b7826e']"

  strings:
    $hex_string = { 0f cc 9e b9 56 4e 6b 90 d1 a1 54 7a 16 88 ff 2c 7b eb bf d2 f0 f8 fa de 84 78 22 b4 10 00 95 c2 2e 74 52 8e c4 13 03 e8 41 f4 f7 50 fb 2a bd 34 f5 3f 6d 14 2d b3 9f 0c cb ae fe a4 17 d8 04 ed }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}