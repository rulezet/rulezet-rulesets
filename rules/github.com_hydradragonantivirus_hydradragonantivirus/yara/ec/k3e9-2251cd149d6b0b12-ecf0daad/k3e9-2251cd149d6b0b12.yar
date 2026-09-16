rule k3e9_2251cd149d6b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2251cd149d6b0b12"
    cluster      = "k3e9.2251cd149d6b0b12"
    cluster_size = "257"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zbot wemosis zusy"
    md5_hashes   = "['0069a8f66da19f81a12745dbec013135','00baff8b39a9590161338d4f9a79a741','1043a0fcad87b08b97e5aee20acd39fa']"

  strings:
    $hex_string = { 5b 9e 24 9e 16 52 e0 b7 e8 63 87 05 20 90 46 83 56 8c 34 88 0d 42 e4 e7 b1 23 82 04 29 90 3a 61 19 5e fa b2 13 be 1e b0 8b c0 22 75 10 5a c9 9d 8b c0 49 da 60 eb 87 73 c3 7b b3 07 72 f2 96 fe }

  condition:
    filesize > 16777216 and filesize < 67108864
    and $hex_string
}